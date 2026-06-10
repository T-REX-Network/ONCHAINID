// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { IAccessManager } from "@openzeppelin/contracts/access/manager/IAccessManager.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { KeyManager } from "../KeyManager.sol";
import { SmartAccount } from "../SmartAccount.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { IdentityProxy } from "../proxy/IdentityProxy.sol";
import { Structs } from "../storage/Structs.sol";
import { Create3 } from "../vendor/utils/Create3.sol";
import { IIdentityFactory } from "./IIdentityFactory.sol";

/// @title IdentityFactory
/// @notice Deploys ONCHAINID identity proxies. Permissions go through an AccessManager.
///         Three deploy paths:
///         - createIdentity: caller deploys for themselves.
///         - createIdentityWithSignature: sponsor deploys, account proves consent via EIP-712.
///           Account is `bytes` so EOA, ERC-1271 and ERC-7913 (passkey, WebAuthn) all work.
///         - createIdentityFor: role-holder deploys for an EVM account that can't sign
///           (a token, a vault). Type must be in the canDeployFor allowlist.
///         All three need msg.sender to hold the per-type role (closed by default).
///         Wallets use the same bytes shape as signers. Bindings are sticky and revocation
///         is terminal. Cross-chain wallet linking (ERC-7930/ERC-7786) is a follow-up.
contract IdentityFactory is IIdentityFactory, AccessManaged, EIP712, Nonces {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev EIP-712 typehash for wallet → identity link.
    bytes32 private constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    /// @dev EIP-712 typehash for sponsored-deploy authorization. keysHash/modulesHash
    ///      lock the bootstrap so a relayer can't swap MANAGEMENT keys after signing.
    bytes32 private constant _CREATE_IDENTITY_TYPEHASH = keccak256(
        "CreateIdentity(bytes account,uint256 identityType,string salt,bytes32 keysHash,bytes32 modulesHash,uint256 nonce,uint256 expiry)"
    );

    /// @notice ImplementationAuthority used by every IdentityProxy this factory deploys.
    address public immutable implementationAuthority;

    /// @dev walletKey = keccak256(signer bytes). Never cleared — sticky binding.
    mapping(bytes32 walletKey => address identity) private _accountIdentity;

    /// @dev Active / Revoked / None. Revoked is final.
    mapping(bytes32 walletKey => AccountStatus status) private _accountStatus;

    /// @dev walletKey → original bytes, for getAccounts() enumeration. Written once.
    mapping(bytes32 walletKey => bytes account) private _accountRecord;

    /// @dev Active wallets per identity. O(1) link/revoke.
    mapping(address identity => EnumerableSet.Bytes32Set walletKeys) private _accounts;

    /// @dev Was this identity deployed here? linkAccount uses it to reject randos.
    mapping(address identity => bool deployedByFactory) private _isFactoryIdentity;

    /// @dev Token → identity (asset path).
    mapping(address => address) private _tokenIdentity;

    /// @dev Identity → token (reverse of _tokenIdentity).
    mapping(address => address) private _tokenAddress;

    /// @dev Identity type → required AccessManager role. 0 means "admin only".
    ///      Role ids are picked by the deployer; this contract doesn't hardcode them.
    mapping(uint256 identityType => uint64 roleId) private _identityTypeRole;

    /// @dev Types that allow createIdentityFor. Off by default; admin opts each one in.
    mapping(uint256 identityType => bool allowed) private _canDeployFor;

    /// @param implementationAuthorityAddress the {ImplementationAuthority} that resolves the
    ///        Identity logic for every proxy this factory deploys.
    /// @param initialAuthority the AccessManager that backs both `restricted` and the
    ///        inline `hasRole` checks in createIdentity*.
    constructor(address implementationAuthorityAddress, address initialAuthority)
        AccessManaged(initialAuthority)
        EIP712("IdentityFactory", "1")
    {
        require(implementationAuthorityAddress != address(0), Errors.ZeroAddress());

        implementationAuthority = implementationAuthorityAddress;
    }

    // ---------------------------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IIdentityFactory
    function setIdentityTypeRole(uint256 _identityType, uint64 _roleId) external override restricted {
        _identityTypeRole[_identityType] = _roleId;
        emit IdentityTypeRoleSet(_identityType, _roleId);
    }

    /// @inheritdoc IIdentityFactory
    function setCanDeployFor(uint256 _identityType, bool _allowed) external override restricted {
        _canDeployFor[_identityType] = _allowed;
        emit CanDeployForSet(_identityType, _allowed);
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
    ) external override returns (address) {
        _checkRole(_identityType, msg.sender);
        // Caller is the account. Auto-link them as the first wallet.
        return _doCreateIdentity(abi.encodePacked(msg.sender), _identityType, _salt, _keys, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentityWithSignature(
        bytes calldata _account,
        uint256 _identityType,
        string calldata _salt,
        Structs.KeyParam[] calldata _keys,
        Structs.ModuleInstall[] calldata _modules,
        uint256 _nonce,
        uint256 _expiry,
        bytes calldata _signature
    ) external override returns (address) {
        // Sponsor must have the role. The account proves consent with its signature.
        _checkRole(_identityType, msg.sender);
        require(block.timestamp <= _expiry, Errors.ExpiredSignature(_expiry));

        // Hash keys + modules into the digest so the relayer can't swap them after signing.
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _CREATE_IDENTITY_TYPEHASH,
                    keccak256(_account),
                    _identityType,
                    keccak256(bytes(_salt)),
                    keccak256(abi.encode(_keys)),
                    keccak256(abi.encode(_modules)),
                    _nonce,
                    _expiry
                )
            )
        );

        // One call covers EOA, ERC-1271 smart wallets, and ERC-7913 verifiers.
        require(SignatureChecker.isValidSignatureNow(_account, digest, _signature), Errors.InvalidSignature());
        _useCheckedNonce(_addressKeyForAccount(_account), _nonce);

        // Auto-link the signer as the first wallet. Bytes shape doesn't matter here.
        return _doCreateIdentity(_account, _identityType, _salt, _keys, _modules);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external override returns (address) {
        _checkRole(_identityType, msg.sender);
        // Only for types the admin explicitly opted in (typically ASSET). For other
        // types, callers must go through createIdentity or createIdentityWithSignature.
        require(_canDeployFor[_identityType], Errors.CannotDeployForType(_identityType));
        require(_account != address(0), Errors.ZeroAddress());
        return _doCreateIdentity(abi.encodePacked(_account), _identityType, _salt, _keys, _modules);
    }

    // ---------------------------------------------------------------------------------------
    // Wallet linking surface
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IIdentityFactory
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry)
        external
        override
    {
        // expiry == 0 reverts (block.timestamp <= 0 is false). Forces callers to pick a window.
        require(block.timestamp <= expiry, Errors.ExpiredSignature(expiry));

        // Only identities this factory deployed can pull wallets in. Otherwise random
        // contracts could register themselves and feed bogus claims to T-REX modules.
        require(_isFactoryIdentity[msg.sender], Errors.NotFactoryIdentity(msg.sender));

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), msg.sender, nonce, expiry))
        );

        // SignatureChecker dispatch — EOA (ECDSA), ERC-1271 (smart wallet), or
        // ERC-7913 (passkey / custom verifier) — one call.
        require(SignatureChecker.isValidSignatureNow(account, digest, signature), Errors.InvalidSignature());

        // Nonce keyed by keccak256(account) cast to address so EVM and non-EVM signers
        // share the OZ Nonces store.
        _useCheckedNonce(_addressKeyForAccount(account), nonce);

        _linkAccount(account, msg.sender);
    }

    /// @inheritdoc IIdentityFactory
    function revokeAccount(bytes calldata account) external override {
        bytes32 key = _walletKey(account);
        require(_accountIdentity[key] == msg.sender, Errors.WalletNotLinkedToIdentity(account));
        _revokeAccount(account, msg.sender);
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IIdentityFactory
    function getIdentity(bytes calldata account) external view override returns (address) {
        bytes32 key = _walletKey(account);
        if (_accountStatus[key] == AccountStatus.Active) {
            return _accountIdentity[key];
        }
        return address(0);
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityIncludingRevoked(bytes calldata account)
        external
        view
        override
        returns (address identity, AccountStatus status)
    {
        bytes32 key = _walletKey(account);
        return (_accountIdentity[key], _accountStatus[key]);
    }

    /// @inheritdoc IIdentityFactory
    function getAccountStatus(bytes calldata account) external view override returns (AccountStatus) {
        return _accountStatus[_walletKey(account)];
    }

    /// @inheritdoc IIdentityFactory
    function getAccounts(address identity) external view override returns (bytes[] memory) {
        return _accountsRange(identity, 0, _accounts[identity].length());
    }

    /// @inheritdoc IIdentityFactory
    function getAccounts(address identity, uint256 start, uint256 end) external view override returns (bytes[] memory) {
        return _accountsRange(identity, start, end);
    }

    /// @inheritdoc IIdentityFactory
    function getToken(address _identity) external view override returns (address) {
        return _tokenAddress[_identity];
    }

    /// @inheritdoc IIdentityFactory
    function getTokenIdentity(address token) external view override returns (address) {
        return _tokenIdentity[token];
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityTypeRole(uint256 _identityType) external view override returns (uint64) {
        return _identityTypeRole[_identityType];
    }

    /// @inheritdoc IIdentityFactory
    function canDeployFor(uint256 _identityType) external view override returns (bool) {
        return _canDeployFor[_identityType];
    }

    /// @inheritdoc IIdentityFactory
    function isFactoryIdentity(address identity) external view override returns (bool) {
        return _isFactoryIdentity[identity];
    }

    /// @inheritdoc IIdentityFactory
    function noncesForAccount(bytes calldata account) external view override returns (uint256) {
        return super.nonces(_addressKeyForAccount(account));
    }

    // ---------------------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------------------

    /// @dev Role 0 (unset) means "admin only" — types are closed by default.
    function _checkRole(uint256 _identityType, address caller) private view {
        uint64 requiredRole = _identityTypeRole[_identityType];
        (bool isMember,) = IAccessManager(authority()).hasRole(requiredRole, caller);
        require(isMember, Errors.NotAuthorizedForIdentityType(caller, _identityType, requiredRole));
    }

    /// @dev keccak256(account) cast to address. Used as the nonce key so OZ Nonces
    ///      (address-keyed) works for ERC-7913 signers (passkeys etc.). Not a real
    ///      account — just a unique slot.
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

        if (_identityType == IdentityTypes.ASSET) {
            // Asset identities are deployed for a token contract — always a 20-byte EVM address.
            require(_account.length == 20, Errors.ZeroAddress());
            address tokenAddr = address(bytes20(_account));
            require(tokenAddr != address(0), Errors.ZeroAddress());

            string memory tokenIdSalt = string.concat("Token", _salt);
            require(_tokenIdentity[tokenAddr] == address(0), Errors.TokenAlreadyLinked(tokenAddr));

            // Salt collisions surface as Create3 FailedDeployment().
            address identity = _deployIdentity(tokenIdSalt, _identityType);

            // CEI: write storage before _setupIdentity runs user-controlled onInstall.
            _tokenIdentity[tokenAddr] = identity;
            _tokenAddress[identity] = tokenAddr;
            _isFactoryIdentity[identity] = true;
            emit TokenLinked(tokenAddr, identity);

            _setupIdentity(identity, _keys, _modules);

            return identity;
        }

        string memory oidSalt = string.concat("OID", _salt);
        address userIdentity = _deployIdentity(oidSalt, _identityType);

        // Mark factory-deployed BEFORE linking so a re-entrant module can't pretend
        // to be a non-factory caller.
        _isFactoryIdentity[userIdentity] = true;
        _linkAccount(_account, userIdentity);

        _setupIdentity(userIdentity, _keys, _modules);

        return userIdentity;
    }

    /// @dev Link rule. Enforces sticky binding, terminal revocation, and the token
    ///      collision guard.
    function _linkAccount(bytes memory account, address identity) internal {
        bytes32 key = _walletKey(account);
        AccountStatus status = _accountStatus[key];

        // Once revoked, never re-linkable.
        require(status != AccountStatus.Revoked, Errors.WalletAlreadyRevoked(account));

        // If already bound, must be the same identity.
        address bound = _accountIdentity[key];
        require(bound == address(0) || bound == identity, Errors.WalletBoundToAnotherIdentity(account, bound));

        // A 20-byte account that's also a registered token can't be a wallet. Non-EVM
        // signers are longer and can't collide.
        if (account.length == 20) {
            address asAddr = address(bytes20(account));
            require(_tokenIdentity[asAddr] == address(0), Errors.TokenAlreadyLinked(asAddr));
        }

        require(_accounts[identity].add(key), Errors.WalletAlreadyLinkedToIdentity(account));

        _accountIdentity[key] = identity;
        _accountStatus[key] = AccountStatus.Active;
        if (_accountRecord[key].length == 0) {
            _accountRecord[key] = account;
        }

        emit AccountLinked(account, identity);
    }

    /// @dev Revoke rule. Flips status to Revoked and drops the wallet from the active
    ///      set. `_accountIdentity` and `_accountRecord` stay so the binding is visible
    ///      via getIdentityIncludingRevoked.
    function _revokeAccount(bytes memory account, address identity) internal {
        bytes32 key = _walletKey(account);
        require(_accountStatus[key] == AccountStatus.Active, Errors.WalletNotActive(account));
        require(_accounts[identity].remove(key), Errors.WalletNotLinkedToIdentity(account));

        _accountStatus[key] = AccountStatus.Revoked;

        emit AccountRevoked(account, identity);
    }

    function _accountsRange(address identity, uint256 start, uint256 end) private view returns (bytes[] memory out) {
        bytes32[] memory keys = _accounts[identity].values(start, end);
        out = new bytes[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            out[i] = _accountRecord[keys[i]];
        }
    }

    function _walletKey(bytes memory account) private pure returns (bytes32) {
        return keccak256(account);
    }

    /// @dev Bootstraps a freshly-deployed identity: add user keys, install modules
    ///      (and grant their MODULE purposes), then drop the factory's bootstrap
    ///      MANAGEMENT key. installModule uses `onlyManager` (not OZ's default
    ///      `onlyEntryPointOrSelf`) — see the NatSpec on SmartAccount.installModule
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

        // 2. Modules. The factory has no opinion on what to install — including the
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

    /// @dev CREATE3 deploy. Address depends only on (factory, salt), so the same salt
    ///      gives the same identity address on every canonical EVM chain where this
    ///      factory shares the same address.
    function _deployIdentity(string memory _salt, uint256 _identityType) private returns (address) {
        bytes memory _code = type(IdentityProxy).creationCode;
        bytes memory _constructData = abi.encode(implementationAuthority, address(this), _identityType);
        bytes memory bytecode = abi.encodePacked(_code, _constructData);

        return Create3.deploy(0, keccak256(abi.encodePacked(_salt)), bytecode);
    }

}
