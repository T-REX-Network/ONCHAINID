// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { IAccessManager } from "@openzeppelin/contracts/access/manager/IAccessManager.sol";
import { ERC7786Recipient } from "@openzeppelin/contracts/crosschain/ERC7786Recipient.sol";
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import { Identity } from "../Identity.sol";
import { IIdentity } from "../interface/IIdentity.sol";
import { Errors } from "../libraries/Errors.sol";
import { hashAddress } from "../libraries/Hashing.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { Create3 } from "@openzeppelin/contracts/utils/Create3.sol";

import { ERC734Validator } from "../modules/validators/ERC734Validator.sol";
import { Structs } from "../storage/Structs.sol";
import { IIdentityFactory } from "./IIdentityFactory.sol";

/// @title IdentityFactory
/// @notice Deploys ONCHAINID identity proxies.
///
///         createIdentity: caller deploys for themselves and is auto-linked as the
///         first wallet. Gated per type by `selfDeployable`. Contract-shaped types
///         like ASSET and SMART_CONTRACT opt out because the `msg.sender = first
///         wallet` binding does not apply to them.
///
///         createIdentityFor: caller deploys for another EVM account and must hold the
///         per-type role. The account signs nothing, which keeps onboarding easy. Instead
///         it has to end up as the only wallet with MANAGEMENT, so the identity is managed
///         by the wallet it was created for. Single binding types (ASSET, SMART_CONTRACT)
///         hold no key, so only the role gate protects them and it must not be PUBLIC_ROLE.
///
///         Admin registers each identity type up front via setIdentityTypePolicy, and the
///         modules it deploys with via setIdentityTypeModules. Unregistered types revert
///         from both entry points. Use the AM's PUBLIC_ROLE for open types. Any other role
///         restricts createIdentityFor to its holders.
///
///         Callers never pass modules. Every identity installs exactly what is registered
///         for its type, so the admin decides which code runs on an identity and with which
///         purpose, not whoever pays for the deploy.
///
///         Wallets and signers share the same bytes shape. Bindings are sticky and
///         revocation is terminal.
///
///         Multicall allows batching several calls in one transaction, e.g. deploying
///         many identities at once. msg.sender is preserved in sub-calls, so role checks
///         behave as in direct calls.
contract IdentityFactory is IIdentityFactory, AccessManaged, EIP712, Nonces, ERC7786Recipient, Multicall {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev EIP-712 typehash for wallet → identity link.
    bytes32 private constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    /// @dev CREATE3 salt for the beacon's predetermined slot.
    bytes32 private constant _BEACON_SALT = keccak256("onchainid.beacon.v1");

    /// @notice OZ UpgradeableBeacon that every BeaconProxy delegates to. Owned by the factory
    ///         itself, so upgrades run through {upgradeBeacon}, which is gated by the factory's
    ///         current authority. Ownership is a stable anchor (the factory address never
    ///         changes) while the real permission follows `authority()`, so an authority
    ///         rotation can never leave a stale account able to upgrade every identity.
    /// @dev The address is a CREATE3 slot committed at construction: it depends only on this
    ///      factory's address and a fixed salt, so it can be an immutable even though the
    ///      beacon itself can only exist after the factory (the beacon needs the Identity
    ///      implementation, which needs the enshrined validator, which needs this factory).
    ///      {initializeBeacon} deploys it there; identity deployment reverts until then.
    address public immutable beacon;

    /// @dev One slot per wallet, keyed by keccak256(signer bytes). identity stays set
    ///      after revoke (sticky binding). record is written once for getAccounts()
    ///      enumeration. status starts at None and is terminal once Revoked.
    struct WalletEntry {
        address identity;
        AccountStatus status;
        bytes record;
    }

    /// @dev Per-type deploy policy. `registered` carries registration explicitly so
    ///      `roleId == 0` (the AM's ADMIN_ROLE) stays usable as a type's required role.
    ///      Unregistered types revert from both deploy entry points. `selfDeployable`
    ///      gates {createIdentity}. `singleBinding` is true for types that represent a
    ///      contract, not a signer (ASSET, SMART_CONTRACT, ...): they keep the one account
    ///      set at deploy and can never link or revoke another. uint64 + three bools pack
    ///      into one storage slot.
    struct TypePolicy {
        uint64 roleId;
        bool selfDeployable;
        bool singleBinding;
        bool registered;
    }

    /// @dev Pending cross-chain link proposed via ERC-7786. `identity` is the
    ///      ONCHAINID on this chain that the wallet has named. The wallet half of
    ///      proof-of-control comes from the authenticated inbound message; the
    ///      identity half comes later when the identity itself calls
    ///      {settlePendingCrossChainLink}. Until then the link is not active.
    struct PendingLink {
        address identity;
        uint256 expiry;
    }

    /// @dev EIP-7201 namespaced storage. All mutable state lives here so a future
    ///      upgrade won't collide with inherited slots.
    /// @custom:storage-location erc7201:onchainid.IdentityFactory
    struct IdentityFactoryStorage {
        mapping(bytes32 walletKey => WalletEntry entry) wallets;
        mapping(address identity => EnumerableSet.Bytes32Set walletKeys) accounts;
        mapping(address identity => bool deployedByFactory) isFactoryIdentity;
        /// @dev Per-type deploy policy. Unregistered types revert.
        mapping(uint256 identityType => TypePolicy policy) typePolicies;
        /// @dev Gateways trusted per origin chain. The key is
        ///      keccak256(chainType, chainReference). Inbound messages from anyone
        ///      else are rejected. Manage via {setTrustedGateway}.
        mapping(address gateway => mapping(bytes32 originKey => bool trusted)) trustedGateways;
        /// @dev Approved ERC-7913 verifiers for {linkAccount}. Signers longer than
        ///      20 bytes only link when their verifier is listed here. Manage via
        ///      {setTrustedVerifier}.
        mapping(address verifier => bool trusted) trustedVerifiers;
        /// @dev Cross-chain link proposals awaiting identity-side confirmation.
        ///      Keyed by {_walletKey} so every encoding of a wallet shares one
        ///      pending slot. Cleared on {settlePendingCrossChainLink}, whether the
        ///      identity accepts or declines.
        mapping(bytes32 walletKey => PendingLink proposal) pendingLinks;
        /// @dev Modules installed on every identity of a given type, set by the admin via
        ///      {setIdentityTypeModules}. Deploy callers pass no modules. This is what makes
        ///      the management guarantee in {createIdentityFor} hold, because a caller cannot
        ///      install a contract of its own and act through it.
        mapping(uint256 identityType => Structs.ModuleInstall[] modules) typeModules;
    }

    // keccak256(abi.encode(uint256(keccak256("onchainid.IdentityFactory")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _IDENTITY_FACTORY_STORAGE_SLOT =
        0x2cefd7c6aca4efb6085e4a9235cc3be23e6beeb0245cf23a279c1cb689649300;

    function _storage() private pure returns (IdentityFactoryStorage storage $) {
        bytes32 slot = _IDENTITY_FACTORY_STORAGE_SLOT;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }

    /// @param initialAuthority AccessManager that backs every `restricted` function here.
    /// @dev The EIP-712 domain version "1" is baked into every wallet link signature made
    ///      against this factory. It is not a release marker and does not follow the identity
    ///      implementation version.
    constructor(address initialAuthority) AccessManaged(initialAuthority) EIP712("IdentityFactory", "1") {
        require(initialAuthority != address(0), Errors.ZeroAddress());
        beacon = Create3.computeAddress(_BEACON_SALT);
    }

    /// @inheritdoc IIdentityFactory
    function initializeBeacon(address implementation) external restricted {
        require(implementation != address(0), Errors.ZeroAddress());
        require(beacon.code.length == 0, Errors.BeaconAlreadyInitialized());
        _checkImplementation(implementation, address(0));
        // Own the beacon from the factory. Upgrades then go through {upgradeBeacon}, which the
        // factory's live authority gates, so ownership never has to be re-transferred on an
        // authority rotation.
        address deployed = Create3.deploy(
            0,
            _BEACON_SALT,
            abi.encodePacked(type(UpgradeableBeacon).creationCode, abi.encode(implementation, address(this)))
        );
        // On chains with a non-canonical CREATE2 derivation (zkSync Era et al.) the beacon lands
        // somewhere other than the address committed in the constructor. Fail loudly instead of
        // leaving the factory permanently pointed at empty code.
        require(deployed == beacon, Errors.BeaconAddressMismatch(beacon, deployed));
        emit BeaconInitialized(implementation);
    }

    /// @inheritdoc IIdentityFactory
    function upgradeBeacon(address newImplementation, string calldata expectedVersion) external restricted {
        require(newImplementation != address(0), Errors.ZeroAddress());
        _checkImplementation(newImplementation, UpgradeableBeacon(beacon).implementation());

        // The version string is compiled into the implementation. Without this check, a build
        // that forgot the version bump would leave every identity reporting a stale release.
        string memory actualVersion = Identity(payable(newImplementation)).version();
        require(
            keccak256(bytes(actualVersion)) == keccak256(bytes(expectedVersion)),
            Errors.ImplementationVersionMismatch(expectedVersion, actualVersion)
        );
        UpgradeableBeacon(beacon).upgradeTo(newImplementation);
        emit BeaconUpgraded(newImplementation);
    }

    /// @dev Shape check for an implementation about to sit behind the beacon. An identity's
    ///      trust anchors are implementation immutables, not proxy storage, so swapping the
    ///      implementation silently re-points every deployed identity at whatever registry the
    ///      new one names. Require the candidate to answer for this factory, to keep the
    ///      outgoing registry when there is one, and to have its own initializers locked.
    ///      `current` is the zero address on the initial deploy, where there is nothing to
    ///      stay continuous with.
    function _checkImplementation(address implementation, address current) private view {
        require(implementation.code.length != 0, Errors.ImplementationNotAContract(implementation));
        require(
            Identity(payable(implementation)).identityFactory() == address(this),
            Errors.ImplementationFactoryMismatch(implementation)
        );
        require(
            Identity(payable(implementation)).initializedVersion() == type(uint64).max,
            Errors.ImplementationInitializersNotDisabled(implementation)
        );

        if (current != address(0)) {
            address expected = Identity(payable(current)).registryModule();
            address actual = Identity(payable(implementation)).registryModule();
            require(actual == expected, Errors.ImplementationRegistryMismatch(expected, actual));
        }
    }

    /// @inheritdoc IIdentityFactory
    function setIdentityTypePolicy(uint256 _identityType, uint64 _roleId, bool _selfDeployable, bool _singleBinding)
        external
        restricted
    {
        // Single binding types skip the sole management check, their role gate is the only
        // thing standing between an open deploy and a hijacked contract identity. Refuse
        // the config instead of trusting every operator to remember that.
        require(!_singleBinding || _roleId != type(uint64).max, Errors.SingleBindingTypeCannotBePublic(_identityType));
        _storage().typePolicies[_identityType] = TypePolicy(_roleId, _selfDeployable, _singleBinding, true);
        emit IdentityTypePolicySet(_identityType, _roleId, _selfDeployable, _singleBinding);
    }

    /// @inheritdoc IIdentityFactory
    function removeIdentityTypePolicy(uint256 _identityType) external restricted {
        delete _storage().typePolicies[_identityType];
        emit IdentityTypePolicyRemoved(_identityType);
    }

    /// @inheritdoc IIdentityFactory
    function setIdentityTypeModules(uint256 _identityType, Structs.ModuleInstall[] calldata _modules)
        external
        restricted
    {
        // Solidity cannot copy a calldata array of structs with dynamic members into
        // storage in one go, so replace the list entry by entry.
        Structs.ModuleInstall[] storage stored = _storage().typeModules[_identityType];
        delete _storage().typeModules[_identityType];
        for (uint256 i = 0; i < _modules.length; i++) {
            stored.push(_modules[i]);
        }
        emit IdentityTypeModulesSet(_identityType, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityTypeModules(uint256 _identityType) external view returns (Structs.ModuleInstall[] memory) {
        return _storage().typeModules[_identityType];
    }

    /// @inheritdoc IIdentityFactory
    function createIdentity(uint256 _identityType, string memory _salt, Structs.KeyParam[] memory _keys)
        external
        returns (address)
    {
        // Self-deploy is gated per type. Contract-shaped types like ASSET / SMART_CONTRACT
        // opt out because their identity represents a contract, not msg.sender.
        TypePolicy storage policy = _storage().typePolicies[_identityType];
        require(policy.registered, Errors.UnknownIdentityType(_identityType));
        require(policy.selfDeployable, Errors.IdentityTypeNotSelfDeployable(_identityType));

        // Always store the wallet as an ERC-7930 envelope. If we stored raw 20-byte
        // addresses here and envelopes in linkAccount, the same wallet would hash to
        // two different keys and sticky binding would not catch the collision.
        bytes memory account = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        return _doCreateIdentity(account, _identityType, _salt, _keys);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys
    ) external returns (address) {
        _checkTypeRole(_identityType, msg.sender);
        require(_account != address(0), Errors.ZeroAddress());
        bytes memory account = InteroperableAddress.formatEvmV1(block.chainid, _account);

        // The identity is created for _account, so _account has to end up managing it. The
        // account signs nothing, which keeps onboarding easy. For signing types the caller
        // may only grant purposes to _account itself: no lesser keys for the caller or
        // anyone else that _account never asked for. _account can add more keys later once
        // it is in control. Single binding types (ASSET, SMART_CONTRACT) are contracts and
        // hold no key, so they skip this and rely on their role gate instead.
        //
        // The check reads the hash derived from signerData, not the caller supplied keyHash
        // field. The registry stores each key under keccak256(signerData) and never reads
        // keyHash, so trusting that field would let a caller pass the account's hash while
        // pointing signerData at its own address.
        bool singleBinding = _storage().typePolicies[_identityType].singleBinding;
        if (!singleBinding) {
            bytes32 accountKey = hashAddress(_account);
            for (uint256 i = 0; i < _keys.length; i++) {
                bytes32 derivedKey = keccak256(_keys[i].signerData);
                require(derivedKey == accountKey, Errors.KeyNotForAccount(derivedKey));
            }
        }

        address identity = _doCreateIdentity(account, _identityType, _salt, _keys);

        if (!singleBinding) {
            _requireSoleManagementKey(identity, _account);
        }

        return identity;
    }

    /// @inheritdoc IIdentityFactory
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external {
        // `account` is an ERC-7930 envelope wrapping the wallet. Its layout is:
        //     [ chainType | chainReference | signer ]
        // bytes feed the signature check. parseV1Calldata reverts on malformed input.
        // The registry is keyed on the canonical re-encoding (see _walletKey), so padded
        // variants of the same wallet all resolve to one entry.
        (bytes2 chainType, bytes calldata chainReference, bytes calldata signer) =
            InteroperableAddress.parseV1Calldata(account);

        // The signature check below only proves control for EVM signers (EOA,
        // ERC-1271, ERC-7913). A foreign-chain envelope proves nothing here, so it
        // must come through the cross-chain path instead. 0x0000 is eip-155.
        require(chainType == 0x0000, Errors.NonEvmAccount(account));

        // The chain reference must name this chain: a signature verified here says
        // nothing about the wallet at that address on another EVM chain, so
        // envelopes for other chains must not link through the signature path.
        require(keccak256(chainReference) == keccak256(_localChainReference()), Errors.AccountNotOnLocalChain(account));

        // An ERC-7913 signer names its own verifier in its first 20 bytes, so the
        // proof is self-certifying unless the verifier is admin-approved.
        if (signer.length > 20) {
            address verifier = address(bytes20(signer[:20]));
            require(isTrustedVerifier(verifier), Errors.UntrustedVerifier(verifier));
        }

        // expiry == 0 reverts (block.timestamp <= 0 is false). Forces callers to pick a window.
        require(block.timestamp <= expiry, Errors.ExpiredSignature(expiry));

        // Only identities this factory deployed can pull wallets in. Otherwise random
        // contracts could register themselves and feed bogus claims to T-REX modules.
        require(_storage().isFactoryIdentity[msg.sender], Errors.NotFactoryIdentity(msg.sender));

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), msg.sender, nonce, expiry))
        );

        // One dispatch covers every supported signer shape:
        //   20 bytes      -> EOA (ECDSA recover) or ERC-1271 smart wallet
        //   20 + N bytes  -> ERC-7913: first 20 bytes = verifier contract,
        //                              rest = signer key (passkey pubkey, RSA key, ...)
        require(SignatureChecker.isValidSignatureNow(signer, digest, signature), Errors.InvalidSignature());

        // Nonce keyed by the canonical wallet key cast to address so every envelope
        // shape (EVM, ERC-7913, future non-EVM) shares the OZ Nonces store and every
        // encoding of the same wallet consumes one nonce sequence.
        _useCheckedNonce(_addressKeyForAccount(account), nonce);

        _linkAccount(account, msg.sender);
    }

    /// @inheritdoc IIdentityFactory
    function revokeAccount(bytes calldata account) external {
        // Symmetric with the link guard: a single-binding identity cannot re-link a
        // fresh account because the bound contract can't sign a LinkAccount digest,
        // so allowing revoke would orphan the factory's discovery entry permanently.
        require(
            !_storage().typePolicies[IIdentity(msg.sender).getIdentityType()].singleBinding,
            Errors.CannotRevokeFromNonSigningIdentity(msg.sender)
        );

        bytes32 key = _walletKey(account);
        require(_storage().wallets[key].identity == msg.sender, Errors.WalletNotLinkedToIdentity(account));
        _revokeAccount(account, msg.sender);
    }

    // ============ ERC-7786 — cross-chain wallet linking ============

    /// @inheritdoc IIdentityFactory
    function setTrustedGateway(address gateway, bytes2 chainType, bytes calldata chainReference, bool trusted)
        external
        restricted
    {
        require(gateway != address(0), Errors.ZeroAddress());
        _storage().trustedGateways[gateway][_originKey(chainType, chainReference)] = trusted;
        emit TrustedGatewaySet(gateway, chainType, chainReference, trusted);
    }

    /// @inheritdoc IIdentityFactory
    function isTrustedGateway(address gateway, bytes2 chainType, bytes calldata chainReference)
        external
        view
        returns (bool)
    {
        return _storage().trustedGateways[gateway][_originKey(chainType, chainReference)];
    }

    /// @inheritdoc IIdentityFactory
    function setTrustedVerifier(address verifier, bool trusted) external restricted {
        require(verifier != address(0), Errors.ZeroAddress());
        _storage().trustedVerifiers[verifier] = trusted;
        emit TrustedVerifierSet(verifier, trusted);
    }

    /// @inheritdoc IIdentityFactory
    function isTrustedVerifier(address verifier) public view returns (bool) {
        return _storage().trustedVerifiers[verifier];
    }

    /// @inheritdoc IIdentityFactory
    function getPendingCrossChainLink(bytes calldata account) external view returns (address identity, uint256 expiry) {
        PendingLink storage pending = _storage().pendingLinks[_walletKey(account)];
        return (pending.identity, pending.expiry);
    }

    /// @inheritdoc IIdentityFactory
    function settlePendingCrossChainLink(bytes calldata account, bool accept) external {
        // The wallet named an identity when it sent the cross-chain message. Only
        // that identity gets to settle the proposal. Anyone else calling here is
        // rejected. The identity reaches us via its own execution path, so a
        // MANAGEMENT key on the identity is what actually signs this off.
        bytes32 key = _walletKey(account);
        PendingLink memory pending = _storage().pendingLinks[key];
        // Missing proposal: `pending.identity == address(0)` never equals
        // `msg.sender`, so one equality check covers both cases.
        require(
            pending.identity == msg.sender,
            Errors.PendingCrossChainLinkIdentityMismatch(account, msg.sender, pending.identity)
        );

        delete _storage().pendingLinks[key];

        // Declining is allowed at any time, expired or not. Accepting is the only
        // other way a slot gets cleared and it reverts once past expiry, so without
        // this a proposal nobody accepted in time would sit here forever.
        if (!accept) {
            emit CrossChainLinkRejected(account, msg.sender, pending.expiry);
            return;
        }

        require(block.timestamp <= pending.expiry, Errors.PendingCrossChainLinkExpired(pending.expiry));
        _linkAccount(account, msg.sender);
        emit CrossChainLinkConfirmed(account, msg.sender);
    }

    /// @dev ERC-7786 gateway authorization. The gateway must be trusted for the
    ///      origin chain encoded in `sender`, so trusting it for one chain does
    ///      not let it deliver from another.
    function _isAuthorizedGateway(address gateway, bytes calldata sender) internal view override returns (bool) {
        (bool success, bytes2 chainType, bytes calldata chainReference,) =
            InteroperableAddress.tryParseV1Calldata(sender);
        return success && _storage().trustedGateways[gateway][_originKey(chainType, chainReference)];
    }

    /// @dev Storage key for one origin chain.
    function _originKey(bytes2 chainType, bytes calldata chainReference) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainType, chainReference));
    }

    /// @dev Decode an inbound cross-chain link proposal and stage it as pending.
    ///      Replay across receiveIds is prevented by the gateway per ERC-7786; we
    ///      add wallet-level replay protection via sticky binding (an active or
    ///      revoked entry blocks fresh proposals from taking effect on confirm).
    function _processMessage(
        address, /* gateway */
        bytes32, /* receiveId */
        bytes calldata sender,
        bytes calldata payload
    )
        internal
        override
    {
        (bytes memory walletEnvelope, address identity, uint256 expiry) = abi.decode(payload, (bytes, address, uint256));

        // The wallet must originate the bridge call itself. `sender` is the
        // source-chain caller authenticated by ERC-7786, so requiring it to
        // equal the wallet envelope is the proof-of-control for the wallet half.
        require(
            keccak256(sender) == keccak256(walletEnvelope),
            Errors.CrossChainSenderWalletMismatch(sender, walletEnvelope)
        );

        // Malformed envelopes fail at delivery instead of surfacing at confirm.
        InteroperableAddress.parseV1(walletEnvelope);

        // A wallet on this chain already has the signature-checked linkAccount path,
        // and a faithful gateway never authenticates a local sender. Accepting one
        // here would link the wallet without its signature.
        (bool isEvm, uint256 chainId,) = InteroperableAddress.tryParseEvmV1(walletEnvelope);
        require(!isEvm || chainId != block.chainid, Errors.CrossChainLinkForLocalWallet(walletEnvelope));

        require(block.timestamp <= expiry, Errors.PendingCrossChainLinkExpired(expiry));
        require(_storage().isFactoryIdentity[identity], Errors.NotFactoryIdentity(identity));

        // The canonical key collapses padded variants of the envelope, so a linked
        // or revoked wallet cannot be re-proposed under a different encoding.
        bytes32 key = _walletKey(walletEnvelope);

        // Sticky binding still applies: a wallet that is already linked or
        // revoked cannot be re-proposed. The confirm step would reject anyway,
        // but failing fast here saves the identity owner a wasted transaction.
        require(_storage().wallets[key].status == AccountStatus.None, Errors.WalletAlreadyHasEntry(walletEnvelope));

        // One pending slot per wallet; the freshest proposal is the one that can
        // be confirmed. Safe to overwrite because the status check above rejects
        // any wallet that is already linked or revoked.
        _storage().pendingLinks[key] = PendingLink({ identity: identity, expiry: expiry });
        emit PendingCrossChainLinkProposed(walletEnvelope, identity, expiry);
    }

    /// @inheritdoc IIdentityFactory
    function getIdentity(bytes calldata account) external view returns (address) {
        WalletEntry storage entry = _storage().wallets[_walletKey(account)];
        return entry.status == AccountStatus.Active ? entry.identity : address(0);
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityIncludingRevoked(bytes calldata account)
        external
        view
        returns (address identity, AccountStatus status)
    {
        WalletEntry storage entry = _storage().wallets[_walletKey(account)];
        return (entry.identity, entry.status);
    }

    /// @inheritdoc IIdentityFactory
    function getAccountStatus(bytes calldata account) external view returns (AccountStatus) {
        return _storage().wallets[_walletKey(account)].status;
    }

    /// @inheritdoc IIdentityFactory
    function getAccounts(address identity, uint256 start, uint256 end) external view returns (bytes[] memory) {
        return _accountsRange(identity, start, end);
    }

    /// @inheritdoc IIdentityFactory
    function getAccountsCount(address identity) external view returns (uint256) {
        return _storage().accounts[identity].length();
    }

    /// @inheritdoc IIdentityFactory
    function isFactoryIdentity(address identity) external view returns (bool) {
        return _storage().isFactoryIdentity[identity];
    }

    /// @inheritdoc IIdentityFactory
    function nonceForAccount(bytes calldata account) external view returns (uint256) {
        return super.nonces(_addressKeyForAccount(account));
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityTypePolicy(uint256 _identityType)
        external
        view
        returns (uint64 roleId, bool selfDeployable, bool singleBinding, bool registered)
    {
        TypePolicy storage policy = _storage().typePolicies[_identityType];
        return (policy.roleId, policy.selfDeployable, policy.singleBinding, policy.registered);
    }

    /// @dev Per-type gate for {createIdentityFor}. Unknown types revert. Admin registers
    ///      a type with `setIdentityTypePolicy` (use the AM's `PUBLIC_ROLE` for open types).
    ///      Memberships carrying an AM execution delay are rejected rather than let the
    ///      delay be silently bypassed — the factory has no scheduling flow.
    function _checkTypeRole(uint256 _identityType, address caller) private view {
        TypePolicy storage policy = _storage().typePolicies[_identityType];
        require(policy.registered, Errors.UnknownIdentityType(_identityType));
        (bool isMember, uint32 executionDelay) = IAccessManager(authority()).hasRole(policy.roleId, caller);
        require(isMember, Errors.NotAuthorizedForIdentityType(caller, _identityType, policy.roleId));
        require(executionDelay == 0, Errors.DelayedRoleNotSupported(caller, policy.roleId, executionDelay));
    }

    /// @dev `block.chainid` encoded as an ERC-7930 chain reference. Round-trips
    ///      through the library so the encoding is exactly the one it emits.
    function _localChainReference() private view returns (bytes memory chainReference) {
        (, chainReference,) = InteroperableAddress.parseV1(InteroperableAddress.formatEvmV1(block.chainid));
    }

    /// @dev {_walletKey} cast to address. Used as the nonce key so OZ Nonces
    ///      (address-keyed) works for ERC-7913 signers (passkeys etc.) and every
    ///      encoding of the same wallet shares one nonce sequence. Not a real
    ///      account, just a unique slot.
    function _addressKeyForAccount(bytes memory account) private pure returns (address) {
        return address(uint160(uint256(_walletKey(account))));
    }

    /// @dev `_account` must be the only wallet holding MANAGEMENT on the new identity.
    ///      MODULE keys never enter the MANAGEMENT index, so the count below only sees
    ///      wallet keys. Callers cannot abuse that exception because the deploy rejects
    ///      caller keys typed MODULE, so the only MODULE keys are the ones the module
    ///      install itself registers. The deployed registry is read rather than `_keys`
    ///      inspected up front, because a module can seed keys through `onInstall`.
    ///      Read through `registryModule()` rather than the account, so a fallback handler
    ///      the caller installed cannot answer these reads (M-04).
    function _requireSoleManagementKey(address identity, address _account) private view {
        ERC734Validator registry = ERC734Validator(Identity(payable(identity)).registryModule());

        require(
            registry.keyHasPurpose(identity, hashAddress(_account), KeyPurposes.MANAGEMENT),
            Errors.AccountNotSoleManagementKey(_account)
        );

        require(
            registry.getKeysByPurpose(identity, KeyPurposes.MANAGEMENT).length == 1,
            Errors.AccountNotSoleManagementKey(_account)
        );
    }

    /// @dev Shared deploy core. CREATE3 deploys the proxy with keys and modules baked into
    ///      the init calldata. Identity.initialize runs in the proxy constructor frame so
    ///      keys and modules are applied without any cross-contract dance and without the
    ///      factory ever holding a MANAGEMENT key. After deploy we check the post-state
    ///      shape (at least one MANAGEMENT key), mark the identity as factory-deployed,
    ///      auto-link the account, and emit TokenLinked for ASSET.
    function _doCreateIdentity(
        bytes memory _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys
    ) private returns (address identity) {
        require(bytes(_salt).length != 0, Errors.EmptyString());
        require(_keys.length > 0, Errors.EmptyListOfKeys());

        // Caller keys are wallet keys. The MODULE type is reserved for the keys the module
        // install registers: MODULE keys stay out of the MANAGEMENT index and cannot sign,
        // so a wallet key labeled MODULE would hold management authority through the
        // approval queue while every count and guard misses it.
        for (uint256 i = 0; i < _keys.length; i++) {
            require(_keys[i].keyType != KeyTypes.MODULE, Errors.CallerKeyCannotBeModule(keccak256(_keys[i].signerData)));
        }

        // Modules come from the type's registered configuration, never from the caller. A
        // type with no modules registered cannot deploy, because Identity.initialize needs
        // a validator or an executor.
        Structs.ModuleInstall[] memory _modules = _storage().typeModules[_identityType];

        // Both entry points build the envelope from a 20-byte EVM address, so the shape is
        // guaranteed here. Asset identities are deployed for a token contract and the token
        // is auto-linked as the identity's sole wallet like any other signer; the difference
        // is the identity's `type`. Off-chain readers can recover the token by reading
        // `getAccounts(identity, 0, 1)[0]` and checking `getIdentityType()`.
        (, address account) = InteroperableAddress.parseEvmV1(_account);
        if (_identityType == IdentityTypes.ASSET) {
            require(account != address(0), Errors.ZeroAddress());
        }

        // Salt covers type, user salt, keys and the account that gets auto-linked, but not
        // modules: a module config change should not move the identity's address, so the
        // same inputs always land at the same slot regardless of which modules are installed
        // at deploy. The account is in there because it is bound to the identity right after
        // this deploy, and the binding is sticky. Leaving it out would let anyone replay a
        // pending creation with an account of their own, take the address the caller was
        // going to get, and have their wallet auto-linked to it. Hashing the parsed address
        // rather than the envelope keeps the address the same across chains.
        bytes32 deploySalt = keccak256(abi.encode(_identityType, _salt, account, keccak256(abi.encode(_keys))));

        identity = _deployIdentity(deploySalt, _identityType, _keys, _modules);

        // The identity must end up with at least one MANAGEMENT key. Without it nobody
        // can manage the identity, so deploy is treated as a programmer error and reverts.
        // Read the enshrined registry directly rather than through the account, so the check
        // is answered by the canonical key store and not by any handler the caller installed.
        // `registryModule()` is a plain function on the beacon-controlled implementation.
        require(
            ERC734Validator(Identity(payable(identity)).registryModule())
            .getKeysByPurpose(identity, KeyPurposes.MANAGEMENT)
            .length >= 1,
            Errors.NoManagementKeyInKeys()
        );

        // Mark factory-deployed BEFORE linking so a re-entrant module can't pretend
        // to be a non-factory caller.
        _storage().isFactoryIdentity[identity] = true;
        _linkAccount(_account, identity);

        if (_identityType == IdentityTypes.ASSET) {
            emit TokenLinked(account, identity);
        }
    }

    /// @dev Link rule. Enforces sticky binding and terminal revocation. Tokens and
    ///      wallets share the same keyspace, so the same address or signer can only
    ///      live in one entry, so there's no separate collision check needed.
    function _linkAccount(bytes memory account, address identity) internal {
        // Normalize first so the key, the stored record and the emitted event all
        // carry the canonical form no matter which encoding the caller supplied.
        // This parses too, so a raw byte string can never become an enumerable record.
        account = _canonicalEnvelope(account);

        // A single-binding identity takes exactly one account: the first, which is
        // the factory's auto-link at deploy. Anything after that would break the
        // 1:1 contract↔identity mapping.
        require(
            !_storage().typePolicies[IIdentity(identity).getIdentityType()].singleBinding
                || _storage().accounts[identity].length() == 0,
            Errors.CannotLinkToAssetIdentity(identity)
        );

        bytes32 key = keccak256(account);
        WalletEntry storage entry = _storage().wallets[key];

        // Once revoked, never re-linkable.
        require(entry.status != AccountStatus.Revoked, Errors.WalletAlreadyRevoked(account));

        // If already bound, must be the same identity.
        require(
            entry.identity == address(0) || entry.identity == identity,
            Errors.WalletBoundToAnotherIdentity(account, entry.identity)
        );

        require(_storage().accounts[identity].add(key), Errors.WalletAlreadyLinkedToIdentity(account));

        entry.identity = identity;
        entry.status = AccountStatus.Active;
        if (entry.record.length == 0) {
            entry.record = account;
        }

        emit AccountLinked(account, identity);
    }

    /// @dev Revoke rule. Flips status to Revoked and drops the wallet from the active
    ///      set. identity + record stay so the binding is visible via
    ///      getIdentityIncludingRevoked. Revoking the last wallet leaves the active set
    ///      empty but the identity manageable: keys are a separate namespace, so a
    ///      MANAGEMENT key can still link a fresh wallet.
    function _revokeAccount(bytes memory account, address identity) internal {
        account = _canonicalEnvelope(account);
        bytes32 key = keccak256(account);
        WalletEntry storage entry = _storage().wallets[key];
        require(entry.status == AccountStatus.Active, Errors.WalletNotActive(account));
        require(_storage().accounts[identity].remove(key), Errors.WalletNotLinkedToIdentity(account));

        entry.status = AccountStatus.Revoked;

        emit AccountRevoked(account, identity);
    }

    function _accountsRange(address identity, uint256 start, uint256 end) private view returns (bytes[] memory out) {
        bytes32[] memory keys = _storage().accounts[identity].values(start, end);
        out = new bytes[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            out[i] = _storage().wallets[keys[i]].record;
        }
    }

    /// @dev Registry key for a wallet: the hash of its canonical envelope. The key
    ///      is canonical by construction, so every valid encoding of a wallet
    ///      resolves to the same entry on every path that touches the registry.
    function _walletKey(bytes memory account) private pure returns (bytes32) {
        return keccak256(_canonicalEnvelope(account));
    }

    /// @dev One wallet must have one encoding, or it would get several registry
    ///      keys. The OZ parser is more lenient than that: it ignores
    ///      trailing bytes and accepts zero-padded eip-155 chain references.
    ///      Re-encoding from the parsed fields drops the trailing bytes; padded
    ///      chain references are rejected. Reverts on invalid envelopes.
    function _canonicalEnvelope(bytes memory account) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, bytes memory addr) = InteroperableAddress.parseV1(account);

        // eip-155 chain references are numeric, so a leading zero byte is padding
        // for the same chainid. Only the minimal encoding (what formatEvmV1 emits)
        // is accepted; a single 0x00 byte is chainid 0 itself, not padding.
        require(
            chainType != 0x0000 || chainReference.length < 2 || chainReference[0] != 0,
            Errors.NonCanonicalAccount(account)
        );

        return InteroperableAddress.formatV1(chainType, chainReference, addr);
    }

    /// @dev CREATE3 deploy of a fresh BeaconProxy. The address depends only on the factory
    ///      address and the deploySalt, so the same salt gives the same identity address
    ///      on every canonical EVM chain where this factory shares the same address. The
    ///      proxy's constructor calls beacon.implementation() and forwards this calldata
    ///      via delegatecall, so Identity.initialize runs inside the new proxy's storage
    ///      and applies keys and modules in the same frame.
    function _deployIdentity(
        bytes32 deploySalt,
        uint256 _identityType,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) private returns (address) {
        require(beacon.code.length != 0, Errors.BeaconNotInitialized());
        bytes memory initData = abi.encodeCall(Identity.initialize, (_identityType, _keys, _modules));
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(beacon, initData));

        return Create3.deploy(0, deploySalt, bytecode);
    }

}
