// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

import { Identity } from "../Identity.sol";
import { KeyManager } from "../KeyManager.sol";
import { SmartAccount } from "../SmartAccount.sol";
import { IIdentity } from "../interface/IIdentity.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { Structs } from "../storage/Structs.sol";
import { Create3 } from "../vendor/utils/Create3.sol";
import { IIdentityFactory } from "./IIdentityFactory.sol";

/// @title IdentityFactory
/// @notice Deploys ONCHAINID identity proxies. Both deploy paths are gated by the
///         AccessManager through `restricted`.
///         createIdentity: caller deploys for themselves and is auto-linked as the
///         first wallet.
///         createIdentityFor: caller deploys for an EVM account that cannot sign
///         (a token, a vault).
///         Admin configures access per selector via `setTargetFunctionRole` on the AM.
///         Wallets and signers share the same bytes shape. Bindings are sticky and
///         revocation is terminal.
contract IdentityFactory is IIdentityFactory, AccessManaged, EIP712, Nonces {

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

    /// @dev EIP-7201 namespaced storage. All mutable state lives here so a future
    ///      upgrade won't collide with inherited slots.
    /// @custom:storage-location erc7201:onchainid.IdentityFactory
    struct IdentityFactoryStorage {
        mapping(bytes32 walletKey => WalletEntry entry) wallets;
        mapping(address identity => EnumerableSet.Bytes32Set walletKeys) accounts;
        mapping(address identity => bool deployedByFactory) isFactoryIdentity;
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

        beacon = beaconAddress;
    }

    // ---------------------------------------------------------------------------------------
    // Deploy paths
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IIdentityFactory
    function createIdentity(
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external restricted returns (address) {
        // Caller is the account. Auto-link them as the first wallet.
        return _doCreateIdentity(abi.encodePacked(msg.sender), _identityType, _salt, _keys, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external restricted returns (address) {
        require(_account != address(0), Errors.ZeroAddress());
        return _doCreateIdentity(abi.encodePacked(_account), _identityType, _salt, _keys, _modules);
    }

    // ---------------------------------------------------------------------------------------
    // Wallet linking surface
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IIdentityFactory
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external {
        // expiry == 0 reverts (block.timestamp <= 0 is false). Forces callers to pick a window.
        require(block.timestamp <= expiry, Errors.ExpiredSignature(expiry));

        // Only identities this factory deployed can pull wallets in. Otherwise random
        // contracts could register themselves and feed bogus claims to T-REX modules.
        require(_storage().isFactoryIdentity[msg.sender], Errors.NotFactoryIdentity(msg.sender));

        // Asset identities represent exactly one token contract. Refuse to add more
        // wallets to them.
        require(
            IIdentity(msg.sender).getIdentityType() != IdentityTypes.ASSET, Errors.CannotLinkToAssetIdentity(msg.sender)
        );

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), msg.sender, nonce, expiry))
        );

        // SignatureChecker dispatch covers EOA (ECDSA), ERC-1271 (smart wallet), and
        // ERC-7913 (passkey, custom verifier) in one call.
        require(SignatureChecker.isValidSignatureNow(account, digest, signature), Errors.InvalidSignature());

        // Nonce keyed by keccak256(account) cast to address so EVM and non-EVM signers
        // share the OZ Nonces store.
        _useCheckedNonce(_addressKeyForAccount(account), nonce);

        _linkAccount(account, msg.sender);
    }

    /// @inheritdoc IIdentityFactory
    function revokeAccount(bytes calldata account) external {
        bytes32 key = _walletKey(account);
        require(_storage().wallets[key].identity == msg.sender, Errors.WalletNotLinkedToIdentity(account));
        _revokeAccount(account, msg.sender);
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

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
    function noncesForAccount(bytes calldata account) external view returns (uint256) {
        return super.nonces(_addressKeyForAccount(account));
    }

    // ---------------------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------------------

    /// @dev keccak256(account) cast to address. Used as the nonce key so OZ Nonces
    ///      (address-keyed) works for ERC-7913 signers (passkeys etc.). Not a real
    ///      account, just a unique slot.
    function _addressKeyForAccount(bytes memory account) private pure returns (address) {
        return address(uint160(uint256(keccak256(account))));
    }

    /// @dev Shared deploy core: CREATE3, mark factory-deployed, auto-link, run bootstrap.
    function _doCreateIdentity(
        bytes memory _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) private returns (address) {
        require(keccak256(bytes(_salt)) != keccak256(""), Errors.EmptyString());
        require(_keys.length > 0, Errors.EmptyListOfKeys());

        // Asset identities are deployed for a token contract, always a 20-byte EVM address.
        // The token is auto-linked as the identity's sole wallet like any other signer;
        // the difference is the identity's `type`. Off-chain readers can recover the
        // token by reading `getAccounts(identity)[0]` and checking `getIdentityType()`.
        if (_identityType == IdentityTypes.ASSET) {
            require(_account.length == 20 && address(bytes20(_account)) != address(0), Errors.ZeroAddress());
        }

        string memory prefixedSalt = string.concat(_identityType == IdentityTypes.ASSET ? "Token" : "OID", _salt);

        // Salt collisions surface as Create3 FailedDeployment().
        address identity = _deployIdentity(prefixedSalt, _identityType);

        // Mark factory-deployed BEFORE linking so a re-entrant module can't pretend
        // to be a non-factory caller.
        _storage().isFactoryIdentity[identity] = true;
        _linkAccount(_account, identity);

        if (_identityType == IdentityTypes.ASSET) {
            emit TokenLinked(address(bytes20(_account)), identity);
        }

        _setupIdentity(identity, _keys, _modules);

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

    /// @dev Bootstraps a freshly-deployed identity: add user keys, install modules
    ///      (and grant their MODULE purposes), then drop the factory's bootstrap
    ///      MANAGEMENT key. installModule uses `onlyManager` (not OZ's default
    ///      `onlyEntryPointOrSelf`). See the NatSpec on SmartAccount.installModule
    ///      for why.
    function _setupIdentity(address _identity, Structs.KeyParam[] memory _keys, Structs.ModuleInstall[] memory _modules)
        private
    {
        // 1. User keys.
        for (uint256 i = 0; i < _keys.length; i++) {
            KeyManager(_identity)
                .addKeyWithData(
                    _keys[i].keyHash, _keys[i].purpose, _keys[i].keyType, _keys[i].signerData, _keys[i].clientData
                );
        }

        // 2. Modules. The factory has no opinion on what to install, including the
        //    legacy ERC-734 execute/approve queue. Callers who want that ABI pass in
        //    the four install entries and grant MANAGEMENT via the install's `purpose`.
        for (uint256 i = 0; i < _modules.length; i++) {
            SmartAccount(payable(_identity))
                .installModule(_modules[i].moduleType, _modules[i].module, _modules[i].initData);
            if (_modules[i].purpose != 0) {
                // Register the module address as a MODULE-type key with that purpose.
                KeyManager(_identity)
                    .addKey(keccak256(abi.encodePacked(_modules[i].module)), _modules[i].purpose, KeyTypes.MODULE);
            }
        }

        // 3. Drop the bootstrap key.
        KeyManager(_identity).removeKey(keccak256(abi.encodePacked(address(this))), KeyPurposes.MANAGEMENT);

        // 4. Must leave at least one MANAGEMENT key behind.
        require(
            KeyManager(_identity).getKeysByPurpose(KeyPurposes.MANAGEMENT).length >= 1, Errors.NoManagementKeyInKeys()
        );
    }

    /// @dev CREATE3 deploy of a fresh BeaconProxy. Address depends only on (factory,
    ///      salt), so the same salt gives the same identity address on every canonical
    ///      EVM chain where this factory shares the same address.
    function _deployIdentity(string memory _salt, uint256 _identityType) private returns (address) {
        // The proxy's constructor calls beacon.implementation() and forwards this
        // calldata via delegatecall, so Identity.initialize runs in the new proxy's
        // storage with the factory as the initial MANAGEMENT key.
        bytes memory initData = abi.encodeCall(Identity.initialize, (address(this), _identityType));
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(beacon, initData));

        return Create3.deploy(0, keccak256(abi.encodePacked(_salt)), bytecode);
    }

}
