// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { IAccessManager } from "@openzeppelin/contracts/access/manager/IAccessManager.sol";
import { ERC7786Recipient } from "@openzeppelin/contracts/crosschain/ERC7786Recipient.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import { Identity } from "../Identity.sol";
import { KeyManager } from "../KeyManager.sol";
import { IIdentity } from "../interface/IIdentity.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { Structs } from "../storage/Structs.sol";
import { Create3 } from "../vendor/utils/Create3.sol";
import { IIdentityFactory } from "./IIdentityFactory.sol";

/// @title IdentityFactory
/// @notice Deploys ONCHAINID identity proxies.
///
///         createIdentity: caller deploys for themselves and is auto-linked as the
///         first wallet. Gated per type by `selfDeployable`. Contract-shaped types
///         like ASSET and SMART_CONTRACT opt out because the `msg.sender = first
///         wallet` binding does not apply to them.
///
///         createIdentityFor: caller deploys for an EVM account that cannot sign
///         (a token, a vault). Caller must hold the per-type role.
///
///         Admin registers each identity type up front via setIdentityTypePolicy.
///         Unregistered types revert from both entry points. Use the AM's PUBLIC_ROLE
///         for open types. Any other role restricts createIdentityFor to its holders.
///
///         Wallets and signers share the same bytes shape. Bindings are sticky and
///         revocation is terminal.
contract IdentityFactory is IIdentityFactory, AccessManaged, EIP712, Nonces, ERC7786Recipient {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev EIP-712 typehash for wallet → identity link.
    bytes32 private constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    /// @notice OZ UpgradeableBeacon that every BeaconProxy delegates to. Its owner
    ///         should be the AccessManager so upgrades go through the same role gating.
    address public immutable beacon;

    /// @dev One slot per wallet, keyed by keccak256(signer bytes). identity stays set
    ///      after revoke (sticky binding). record is written once for getAccounts()
    ///      enumeration. status starts at None and is terminal once Revoked.
    struct WalletEntry {
        address identity;
        AccountStatus status;
        bytes record;
    }

    /// @dev Per-type deploy policy. `roleId == 0` means the type is unregistered;
    ///      both deploy entry points revert. `selfDeployable` gates {createIdentity}.
    ///      uint64 + bool pack into one storage slot.
    struct TypePolicy {
        uint64 roleId;
        bool selfDeployable;
    }

    /// @dev Pending cross-chain link proposed via ERC-7786. `identity` is the
    ///      ONCHAINID on this chain that the wallet has named. The wallet half of
    ///      proof-of-control comes from the authenticated inbound message; the
    ///      identity half comes later when the identity itself calls
    ///      {confirmCrossChainLink}. Until then the link is not active.
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
        /// @dev Per-type deploy policy. Unregistered types (`roleId == 0`) revert.
        mapping(uint256 identityType => TypePolicy policy) typePolicies;
        /// @dev Authorized ERC-7786 destination gateways. Inbound messages from
        ///      anyone else are rejected. Manage via {setTrustedGateway}.
        mapping(address gateway => bool trusted) trustedGateways;
        /// @dev Cross-chain link proposals awaiting identity-side confirmation.
        ///      Keyed by the wallet envelope bytes. Cleared on {confirmCrossChainLink}.
        mapping(bytes wallet => PendingLink proposal) pendingLinks;
    }

    // keccak256(abi.encode(uint256(keccak256("onchainid.IdentityFactory")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _IDENTITY_FACTORY_STORAGE_SLOT =
        0x2cefd7c6aca4efb6085e4a9235cc3be23e6beeb0245cf23a279c1cb689649300;

    function _storage() private pure returns (IdentityFactoryStorage storage $) {
        bytes32 slot = _IDENTITY_FACTORY_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /// @param beaconAddress OZ UpgradeableBeacon every deployed proxy delegates to.
    /// @param initialAuthority AccessManager that backs every `restricted` function here.
    constructor(address beaconAddress, address initialAuthority)
        AccessManaged(initialAuthority)
        EIP712("IdentityFactory", "1")
    {
        require(beaconAddress != address(0), Errors.ZeroAddress());
        require(initialAuthority != address(0), Errors.ZeroAddress());

        beacon = beaconAddress;
    }

    /// @inheritdoc IIdentityFactory
    function setIdentityTypePolicy(uint256 _identityType, uint64 _roleId, bool _selfDeployable) external restricted {
        _storage().typePolicies[_identityType] = TypePolicy(_roleId, _selfDeployable);
        emit IdentityTypePolicySet(_identityType, _roleId, _selfDeployable);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentity(
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address) {
        // Self-deploy is gated per type. Contract-shaped types like ASSET / SMART_CONTRACT
        // opt out because their identity represents a contract, not msg.sender.
        TypePolicy storage policy = _storage().typePolicies[_identityType];
        require(policy.roleId != 0, Errors.UnknownIdentityType(_identityType));
        require(policy.selfDeployable, Errors.IdentityTypeNotSelfDeployable(_identityType));

        // Always store the wallet as an ERC-7930 envelope. If we stored raw 20-byte
        // addresses here and envelopes in linkAccount, the same wallet would hash to
        // two different keys and sticky binding would not catch the collision.
        bytes memory account = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        return _doCreateIdentity(account, _identityType, _salt, _keys, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address) {
        _checkTypeRole(_identityType, msg.sender);
        require(_account != address(0), Errors.ZeroAddress());
        bytes memory account = InteroperableAddress.formatEvmV1(block.chainid, _account);
        return _doCreateIdentity(account, _identityType, _salt, _keys, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external {
        // `account` is an ERC-7930 envelope wrapping the wallet. Its layout is:
        //     [ chainType | chainReference | signer ]
        // bytes feed the signature check. parseV1Calldata reverts on malformed input.
        (,, bytes calldata signer) = InteroperableAddress.parseV1Calldata(account);

        // expiry == 0 reverts (block.timestamp <= 0 is false). Forces callers to pick a window.
        require(block.timestamp <= expiry, Errors.ExpiredSignature(expiry));

        // Only identities this factory deployed can pull wallets in. Otherwise random
        // contracts could register themselves and feed bogus claims to T-REX modules.
        require(_storage().isFactoryIdentity[msg.sender], Errors.NotFactoryIdentity(msg.sender));

        // Non-signing-entity identities (ASSET, SMART_CONTRACT) are bound to one contract
        // at deploy. Adding more wallets to them would break the 1:1 contract↔identity
        // mapping.
        uint256 idType = IIdentity(msg.sender).getIdentityType();
        require(
            idType != IdentityTypes.ASSET && idType != IdentityTypes.SMART_CONTRACT,
            Errors.CannotLinkToAssetIdentity(msg.sender)
        );

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), msg.sender, nonce, expiry))
        );

        // One dispatch covers every supported signer shape:
        //   20 bytes      -> EOA (ECDSA recover) or ERC-1271 smart wallet
        //   20 + N bytes  -> ERC-7913: first 20 bytes = verifier contract,
        //                              rest = signer key (passkey pubkey, RSA key, ...)
        require(SignatureChecker.isValidSignatureNow(signer, digest, signature), Errors.InvalidSignature());

        // Nonce keyed by keccak256(account) cast to address so every envelope shape
        // (EVM, ERC-7913, future non-EVM) shares the OZ Nonces store.
        _useCheckedNonce(_addressKeyForAccount(account), nonce);

        _linkAccount(account, msg.sender);
    }

    /// @inheritdoc IIdentityFactory
    function revokeAccount(bytes calldata account) external {
        // Symmetric with the linkAccount ASSET guard: non-signing-entity identities (ASSET,
        // SMART_CONTRACT) cannot re-link a fresh wallet because the bound contract can't
        // sign a LinkAccount digest. Allowing revoke would orphan the factory's discovery
        // entry permanently. Block it.
        uint256 idType = IIdentity(msg.sender).getIdentityType();
        require(
            idType != IdentityTypes.ASSET && idType != IdentityTypes.SMART_CONTRACT,
            Errors.CannotRevokeFromNonSigningIdentity(msg.sender)
        );

        bytes32 key = _walletKey(account);
        require(_storage().wallets[key].identity == msg.sender, Errors.WalletNotLinkedToIdentity(account));
        _revokeAccount(account, msg.sender);
    }

    // ============ ERC-7786 — cross-chain wallet linking ============

    /// @inheritdoc IIdentityFactory
    function setTrustedGateway(address gateway, bool trusted) external restricted {
        require(gateway != address(0), Errors.ZeroAddress());
        _storage().trustedGateways[gateway] = trusted;
        emit TrustedGatewaySet(gateway, trusted);
    }

    /// @inheritdoc IIdentityFactory
    function isTrustedGateway(address gateway) external view returns (bool) {
        return _storage().trustedGateways[gateway];
    }

    /// @inheritdoc IIdentityFactory
    function getPendingCrossChainLink(bytes calldata account) external view returns (address identity, uint256 expiry) {
        PendingLink storage pending = _storage().pendingLinks[account];
        return (pending.identity, pending.expiry);
    }

    /// @inheritdoc IIdentityFactory
    function confirmCrossChainLink(bytes calldata account) external {
        // The wallet named an identity when it sent the cross-chain message. Only
        // that identity gets to finalize the link. Anyone else calling here is
        // rejected. The identity reaches us via its own execution path, so a
        // MANAGEMENT key on the identity is what actually signs this off.
        PendingLink memory pending = _storage().pendingLinks[account];
        // `pending.identity == address(0)` when no proposal exists, which can never
        // equal `msg.sender`, so a single equality check covers both the missing-
        // proposal and wrong-identity cases.
        require(
            pending.identity == msg.sender,
            Errors.PendingCrossChainLinkIdentityMismatch(account, msg.sender, pending.identity)
        );
        require(block.timestamp <= pending.expiry, Errors.PendingCrossChainLinkExpired(pending.expiry));

        delete _storage().pendingLinks[account];
        _linkAccount(account, msg.sender);
        emit CrossChainLinkConfirmed(account, msg.sender);
    }

    /// @dev ERC-7786 gateway authorization. The factory delegates trust to its
    ///      AccessManager: only addresses the AM admin has whitelisted via
    ///      {setTrustedGateway} can deliver inbound messages.
    function _isAuthorizedGateway(
        address gateway,
        bytes calldata /* sender */
    )
        internal
        view
        override
        returns (bool)
    {
        return _storage().trustedGateways[gateway];
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
        require(block.timestamp <= expiry, Errors.PendingCrossChainLinkExpired(expiry));
        require(_storage().isFactoryIdentity[identity], Errors.NotFactoryIdentity(identity));

        // Sticky binding still applies: a wallet that is already linked or
        // revoked cannot be re-proposed. The confirm step would reject anyway,
        // but failing fast here saves the identity owner a wasted transaction.
        require(
            _storage().wallets[_walletKey(walletEnvelope)].status == AccountStatus.None,
            Errors.WalletAlreadyHasEntry(walletEnvelope)
        );

        _storage().pendingLinks[walletEnvelope] = PendingLink({ identity: identity, expiry: expiry });
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
    function getAccounts(address identity) external view returns (bytes[] memory) {
        return _accountsRange(identity, 0, _storage().accounts[identity].length());
    }

    /// @inheritdoc IIdentityFactory
    function getAccounts(address identity, uint256 start, uint256 end) external view returns (bytes[] memory) {
        return _accountsRange(identity, start, end);
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
    function getIdentityTypePolicy(uint256 _identityType) external view returns (uint64 roleId, bool selfDeployable) {
        TypePolicy storage policy = _storage().typePolicies[_identityType];
        return (policy.roleId, policy.selfDeployable);
    }

    /// @dev Per-type gate for {createIdentityFor}. Unknown types revert. Admin registers
    ///      a type with `setIdentityTypePolicy` (use the AM's `PUBLIC_ROLE` for open types).
    function _checkTypeRole(uint256 _identityType, address caller) private view {
        uint64 requiredRole = _storage().typePolicies[_identityType].roleId;
        require(requiredRole != 0, Errors.UnknownIdentityType(_identityType));
        (bool isMember,) = IAccessManager(authority()).hasRole(requiredRole, caller);
        require(isMember, Errors.NotAuthorizedForIdentityType(caller, _identityType, requiredRole));
    }

    /// @dev keccak256(account) cast to address. Used as the nonce key so OZ Nonces
    ///      (address-keyed) works for ERC-7913 signers (passkeys etc.). Not a real
    ///      account, just a unique slot.
    function _addressKeyForAccount(bytes memory account) private pure returns (address) {
        return address(uint160(uint256(keccak256(account))));
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
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) private returns (address) {
        require(bytes(_salt).length != 0, Errors.EmptyString());
        require(_keys.length > 0, Errors.EmptyListOfKeys());

        // Asset identities are deployed for a token contract, always a 20-byte EVM address.
        // The token is auto-linked as the identity's sole wallet like any other signer;
        // the difference is the identity's `type`. Off-chain readers can recover the
        // token by reading `getAccounts(identity)[0]` and checking `getIdentityType()`.
        // The envelope is built by the factory itself, so the EVM shape is guaranteed;
        // the meaningful check here is just that the address inside is non-zero.
        if (_identityType == IdentityTypes.ASSET) {
            (, address evmAddr) = InteroperableAddress.parseEvmV1(_account);
            require(evmAddr != address(0), Errors.ZeroAddress());
        }

        // Salt covers every deploy input, so different keys give different addresses.
        bytes32 deploySalt = keccak256(
            abi.encode(_identityType, _salt, keccak256(abi.encode(_keys)), keccak256(abi.encode(_modules)))
        );

        address identity = _deployIdentity(deploySalt, _identityType, _keys, _modules);

        // The identity must end up with at least one MANAGEMENT key. Without it nobody
        // can manage the identity, so deploy is treated as a programmer error and reverts.
        require(
            KeyManager(identity).getKeysByPurpose(KeyPurposes.MANAGEMENT).length >= 1, Errors.NoManagementKeyInKeys()
        );

        // Mark factory-deployed BEFORE linking so a re-entrant module can't pretend
        // to be a non-factory caller.
        _storage().isFactoryIdentity[identity] = true;
        _linkAccount(_account, identity);

        if (_identityType == IdentityTypes.ASSET) {
            (, address evmAddr) = InteroperableAddress.parseEvmV1(_account);
            emit TokenLinked(evmAddr, identity);
        }

        return identity;
    }

    /// @dev Link rule. Enforces sticky binding and terminal revocation. Tokens and
    ///      wallets share the same keyspace, so the same address or signer can only
    ///      live in one entry, so there's no separate collision check needed.
    function _linkAccount(bytes memory account, address identity) internal {
        bytes32 key = _walletKey(account);
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
    ///      getIdentityIncludingRevoked.
    function _revokeAccount(bytes memory account, address identity) internal {
        bytes32 key = _walletKey(account);
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

    function _walletKey(bytes memory account) private pure returns (bytes32) {
        return keccak256(account);
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
        bytes memory initData = abi.encodeCall(Identity.initialize, (_identityType, _keys, _modules));
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(beacon, initData));

        return Create3.deploy(0, deploySalt, bytecode);
    }

}
