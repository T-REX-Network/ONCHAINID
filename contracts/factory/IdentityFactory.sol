// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { IAccessManager } from "@openzeppelin/contracts/access/manager/IAccessManager.sol";

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
/// @notice Factory for ONCHAINID identity proxies. Authorization is delegated to an
///         OpenZeppelin AccessManager (see {AccessManaged}):
///
///         - {createIdentity} resolves `_identityType -> roleId` from {getIdentityTypeRole}
///           and checks membership inline via `IAccessManager.hasRole`. Types that have
///           never been opened via {setIdentityTypeRole} default to `ADMIN_ROLE`
///           (closed), so deployment of a brand-new identity type requires an explicit
///           admin action.
///         - {setIdentityTypeRole} is marked `restricted`, so it follows the standard
///           AccessManager flow (per-target admin delay, scheduling, guardians).
///
///         The factory orchestrates bootstrap directly: it holds a transient MANAGEMENT
///         key on the freshly deployed identity, installs caller-supplied keys and
///         modules, grants module purposes, and finally drops its bootstrap key. The
///         post-setup invariant guarantees the identity exits with at least one
///         MANAGEMENT key it does not itself hold.
contract IdentityFactory is IIdentityFactory, AccessManaged {

    // address of the _implementationAuthority contract making the link to the implementation contract
    address public immutable implementationAuthority;

    // ONCHAINID of the wallet owner
    mapping(address => address) private _userIdentity;

    // wallets currently linked to an ONCHAINID
    mapping(address => address[]) private _wallets;

    // ONCHAINID of the token
    mapping(address => address) private _tokenIdentity;

    // token linked to an ONCHAINID
    mapping(address => address) private _tokenAddress;

    /// @dev Identity-type to AccessManager role mapping. A zero entry means the type
    ///      defaults to `ADMIN_ROLE` (closed). The factory does not hardcode role ids;
    ///      they are deployer-chosen `uint64`s wired by the AccessManager admin.
    mapping(uint256 identityType => uint64 roleId) private _identityTypeRole;

    /// @param implementationAuthorityAddress the {ImplementationAuthority} that resolves the
    ///        Identity logic for every proxy deployed by this factory.
    /// @param initialAuthority the {AccessManager} address that will gate all `restricted`
    ///        functions and back the `IAccessManager.hasRole` checks inside {createIdentity}.
    constructor(address implementationAuthorityAddress, address initialAuthority) AccessManaged(initialAuthority) {
        require(implementationAuthorityAddress != address(0), Errors.ZeroAddress());

        implementationAuthority = implementationAuthorityAddress;
    }

    /// @inheritdoc IIdentityFactory
    function setIdentityTypeRole(uint256 _identityType, uint64 _roleId) external override restricted {
        _identityTypeRole[_identityType] = _roleId;
        emit IdentityTypeRoleSet(_identityType, _roleId);
    }

    /// @inheritdoc IIdentityFactory
    function createIdentity(
        address _subject,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external override returns (address) {
        // Per-type AccessManager gate. `_identityTypeRole[_identityType] == 0` means
        // "never opened" => only ADMIN_ROLE (id 0) may create this type.
        uint64 requiredRole = _identityTypeRole[_identityType];
        (bool isMember,) = IAccessManager(authority()).hasRole(requiredRole, msg.sender);
        require(isMember, Errors.NotAuthorizedForIdentityType(msg.sender, _identityType, requiredRole));

        require(_subject != address(0), Errors.ZeroAddress());
        require(keccak256(bytes(_salt)) != keccak256(""), Errors.EmptyString());
        require(_keys.length > 0, Errors.EmptyListOfKeys());

        if (_identityType == IdentityTypes.ASSET) {
            string memory tokenIdSalt = string.concat("Token", _salt);
            require(_tokenIdentity[_subject] == address(0), Errors.TokenAlreadyLinked(_subject));

            // Salt-collision protection comes from Create3: reverts with `FailedDeployment()`
            // if `tokenIdSalt` has already been used on this factory.
            address identity = _deployIdentity(tokenIdSalt, _identityType);

            // Checks-effects-interactions: commit storage BEFORE `_setupIdentity` runs user-controlled `onInstall`.
            _tokenIdentity[_subject] = identity;
            _tokenAddress[identity] = _subject;
            emit TokenLinked(_subject, identity);

            _setupIdentity(identity, _keys, _modules);

            return identity;
        }

        string memory oidSalt = string.concat("OID", _salt);
        require(_userIdentity[_subject] == address(0), Errors.WalletAlreadyLinkedToIdentity(_subject));

        // Salt-collision protection comes from Create3 itself: `_deployIdentity` reverts with
        // `FailedDeployment()` if `oidSalt` has already been used on this factory.
        address userIdentity = _deployIdentity(oidSalt, _identityType);

        // Checks-effects-interactions: commit storage BEFORE any user-controlled `onInstall`
        // runs in `_setupIdentity`. A malicious module re-entering `createIdentity` for the
        // same wallet now hits `_userIdentity[_subject] != 0` and reverts before a second
        // deployment can occur.
        _userIdentity[_subject] = userIdentity;
        _wallets[userIdentity].push(_subject);
        emit WalletLinked(_subject, userIdentity);

        _setupIdentity(userIdentity, _keys, _modules);

        return userIdentity;
    }

    /// @inheritdoc IIdentityFactory
    function linkWallet(address _newWallet) external override {
        require(_newWallet != address(0), Errors.ZeroAddress());
        require(_userIdentity[msg.sender] != address(0), Errors.WalletNotLinkedToIdentity(msg.sender));
        require(_userIdentity[_newWallet] == address(0), Errors.WalletAlreadyLinkedToIdentity(_newWallet));
        require(_tokenIdentity[_newWallet] == address(0), Errors.TokenAlreadyLinked(_newWallet));
        address identity = _userIdentity[msg.sender];
        require(_wallets[identity].length < 101, Errors.MaxWalletsPerIdentityExceeded());
        _userIdentity[_newWallet] = identity;
        _wallets[identity].push(_newWallet);
        emit WalletLinked(_newWallet, identity);
    }

    /// @inheritdoc IIdentityFactory
    function unlinkWallet(address _oldWallet) external override {
        require(_oldWallet != address(0), Errors.ZeroAddress());
        require(_oldWallet != msg.sender, Errors.CannotBeCalledOnSenderAddress());
        require(_userIdentity[msg.sender] == _userIdentity[_oldWallet], Errors.OnlyLinkedWalletCanUnlink());
        address _identity = _userIdentity[_oldWallet];
        delete _userIdentity[_oldWallet];
        uint256 length = _wallets[_identity].length;
        for (uint256 i = 0; i < length; i++) {
            if (_wallets[_identity][i] == _oldWallet) {
                _wallets[_identity][i] = _wallets[_identity][length - 1];
                _wallets[_identity].pop();
                break;
            }
        }
        emit WalletUnlinked(_oldWallet, _identity);
    }

    /// @inheritdoc IIdentityFactory
    function getIdentity(address _wallet) external view override returns (address) {
        if (_tokenIdentity[_wallet] != address(0)) {
            return _tokenIdentity[_wallet];
        }

        return _userIdentity[_wallet];
    }

    /// @inheritdoc IIdentityFactory
    function getWallets(address _identity) external view override returns (address[] memory) {
        return _wallets[_identity];
    }

    /// @inheritdoc IIdentityFactory
    function getToken(address _identity) external view override returns (address) {
        return _tokenAddress[_identity];
    }

    /// @inheritdoc IIdentityFactory
    function getIdentityTypeRole(uint256 _identityType) external view override returns (uint64) {
        return _identityTypeRole[_identityType];
    }

    /// @dev Bootstraps a freshly-deployed identity:
    ///      1. Adds user-supplied keys (factory holds bootstrap MANAGEMENT).
    ///      2. Installs caller-supplied modules and, when requested, registers each
    ///         module address as a `MODULE`-type key under the requested purpose so it
    ///         can dispatch through {SmartAccount.executeFromExecutor}.
    ///      3. Removes the factory's bootstrap MANAGEMENT key.
    ///
    ///      Module installation goes through {SmartAccount.installModule}, which is
    ///      gated by `onlyManager` (see the NatSpec there for why the OZ default
    ///      `onlyEntryPointOrSelf` is deliberately not used during bootstrap).
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

        // 2. Caller-supplied modules. The factory takes no opinion on which modules belong
        //    on the identity — including the queue module that powers the legacy ERC-734
        //    `execute`/`approve` ABI. Callers who want that ABI include the four install
        //    entries (1 executor + 3 fallbacks for execute/approve/getCurrentNonce) and
        //    grant the queue module MANAGEMENT purpose via `purpose` on the install entry.
        for (uint256 i = 0; i < _modules.length; i++) {
            SmartAccount(payable(_identity))
                .installModule(_modules[i].moduleType, _modules[i].module, _modules[i].initData);
            if (_modules[i].purpose != 0) {
                // Register the module address as a key under `MODULE` keyType.
                KeyManager(_identity)
                    .addKey(keccak256(abi.encodePacked(_modules[i].module)), _modules[i].purpose, KeyTypes.MODULE);
            }
        }

        // 3. Drop the bootstrap key.
        KeyManager(_identity).removeKey(keccak256(abi.encodePacked(address(this))), KeyPurposes.MANAGEMENT);

        // 4. Assert the post-setup invariant: the identity owns at least one MANAGEMENT key.
        require(
            KeyManager(_identity).getKeysByPurpose(KeyPurposes.MANAGEMENT).length >= 1, Errors.NoManagementKeyInKeys()
        );
    }

    // function used to deploy an identity using CREATE3.
    // The deployed address depends only on (address(this), salt), so the same salt yields the
    // same Identity address on every canonical-EVM chain when this factory shares the same address.
    function _deployIdentity(string memory _salt, uint256 _identityType) private returns (address) {
        bytes memory _code = type(IdentityProxy).creationCode;
        bytes memory _constructData = abi.encode(implementationAuthority, address(this), _identityType);
        bytes memory bytecode = abi.encodePacked(_code, _constructData);

        return Create3.deploy(0, keccak256(abi.encodePacked(_salt)), bytecode);
    }

}
