// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { KeyManager } from "../KeyManager.sol";
import { SmartAccount } from "../SmartAccount.sol";
import { IClaimIssuer } from "../interface/IClaimIssuer.sol";
import { IERC735 } from "../interface/IERC735.sol";
import { IIdentity } from "../interface/IIdentity.sol";
import { IKeyExecutor } from "../interface/IKeyExecutor.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { IdentityProxy } from "../proxy/IdentityProxy.sol";
import { Structs } from "../storage/Structs.sol";
import { Create3 } from "../vendor/utils/Create3.sol";
import { LowLevelCall } from "../vendor/utils/LowLevelCall.sol";
import { IIdFactory } from "./IIdFactory.sol";

contract IdFactory is IIdFactory, Ownable {

    using EnumerableSet for EnumerableSet.AddressSet;

    // address of the _implementationAuthority contract making the link to the implementation contract
    address public immutable implementationAuthority;

    // address of the ERC-7579 default modules
    address public immutable _erc7579Signature;
    address public immutable _keyApprovalModule;
    address public immutable _claimsModule;

    EnumerableSet.AddressSet private _tokenFactories;

    // ONCHAINID of any address bound to it (account wallet or token contract)
    mapping(address => address) private _accountIdentity;

    // addresses currently linked to an ONCHAINID (single-entry for token identities)
    mapping(address => EnumerableSet.AddressSet) private _accounts;

    // setting
    constructor(
        address implementationAuthorityAddress,
        address owner,
        address erc7579Signature,
        address keyApprovalModule,
        address claimsModule
    ) Ownable(owner) {
        require(implementationAuthorityAddress != address(0), Errors.ZeroAddress());

        implementationAuthority = implementationAuthorityAddress;
        _erc7579Signature = erc7579Signature;
        _keyApprovalModule = keyApprovalModule;
        _claimsModule = claimsModule;
    }

    /**
     *  @dev See {IdFactory-addTokenFactory}.
     */
    function addTokenFactory(address _factory) public onlyOwner {
        require(_factory != address(0), Errors.ZeroAddress());
        require(_tokenFactories.add(_factory), Errors.AlreadyAFactory(_factory));
        emit TokenFactoryAdded(_factory);
    }

    /**
     *  @dev See {IdFactory-removeTokenFactory}.
     */
    function removeTokenFactory(address _factory) public onlyOwner {
        require(_factory != address(0), Errors.ZeroAddress());
        require(_tokenFactories.remove(_factory), Errors.NotAFactory(_factory));
        emit TokenFactoryRemoved(_factory);
    }

    /**
     *  @dev See {IIdFactory-createIdentity}.
     */
    function createIdentity(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) public returns (address) {
        bool isAsset = _identityType == IdentityTypes.ASSET;
        require(
            isAsset ? (isTokenFactory(_msgSender()) || _msgSender() == owner()) : _msgSender() == owner(),
            Ownable.OwnableUnauthorizedAccount(_msgSender())
        );
        require(_account != address(0), Errors.ZeroAddress());
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1 + _keys.length);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(_account)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(_account),
            clientData: ""
        });
        for (uint256 i = 0; i < _keys.length; i++) {
            keys[1 + i] = _keys[i];
        }

        string memory prefixedSalt = string.concat(isAsset ? "Token" : "OID", _salt);

        // Factory ships every identity with the full default surface so callers don't have to
        // assemble it themselves:
        //   - 1 signature validator,
        //   - KeyApprovalModule (executor + fallback for the legacy ERC-734 execute/approve ABI),
        //   - ClaimsModule (executor + fallback for the ERC-735 / ClaimIssuer surface).
        // Additional caller-supplied modules are appended after.
        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](16 + _modules.length);
        modules[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR, module: _erc7579Signature, initData: "", purpose: 0
        });
        // KeyApprovalModule: granted MANAGEMENT so the queue can dispatch self-targeted calls
        // (e.g. addKey, removeKey) via `executeFromExecutor`.
        modules[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: _keyApprovalModule, initData: "", purpose: KeyPurposes.MANAGEMENT
        });
        modules[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.execute.selector),
            purpose: 0
        });
        modules[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.approve.selector),
            purpose: 0
        });
        modules[4] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.getCurrentNonce.selector),
            purpose: 0
        });
        modules[5] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: _claimsModule, initData: "", purpose: 0
        });
        modules[6] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IERC735.addClaim.selector),
            purpose: 0
        });
        modules[7] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IERC735.removeClaim.selector),
            purpose: 0
        });
        modules[8] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IERC735.getClaim.selector),
            purpose: 0
        });
        modules[9] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IERC735.getClaimIdsByTopic.selector),
            purpose: 0
        });
        modules[10] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IIdentity.isClaimValid.selector),
            purpose: 0
        });
        modules[11] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IIdentity.getClaimHash.selector),
            purpose: 0
        });
        modules[12] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IClaimIssuer.revokeClaim.selector),
            purpose: 0
        });
        modules[13] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IClaimIssuer.revokeClaimBySignature.selector),
            purpose: 0
        });
        modules[14] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IClaimIssuer.isClaimRevoked.selector),
            purpose: 0
        });
        modules[15] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: _claimsModule,
            initData: abi.encodePacked(IClaimIssuer.addClaimTo.selector),
            purpose: 0
        });
        for (uint256 i = 0; i < _modules.length; i++) {
            modules[16 + i] = _modules[i];
        }

        address identity = _deployIdentity(prefixedSalt, _identityType, keys, modules);

        _linkAccount(_account, identity);

        return identity;
    }

    /**
     *  @dev See {IdFactory-linkAccount}.
     */
    function linkAccount(address _newAccount) public {
        require(_newAccount != address(0), Errors.ZeroAddress());
        address identity = getIdentity(_msgSender());
        require(identity != address(0), Errors.AccountNotLinkedToIdentity(_msgSender()));
        require(IIdentity(identity).getIdentityType() != IdentityTypes.ASSET, Errors.TokenAlreadyLinked(identity));
        _linkAccount(_newAccount, identity);
    }

    /**
     *  @dev See {IdFactory-unlinkAccount}.
     */
    function unlinkAccount(address _oldAccount) public {
        require(_oldAccount != address(0), Errors.ZeroAddress());
        require(_oldAccount != _msgSender(), Errors.CannotBeCalledOnSenderAddress());
        address _identity = getIdentity(_oldAccount);
        require(_identity != address(0), Errors.AccountNotLinkedToIdentity(_oldAccount));
        require(getIdentity(_msgSender()) == _identity, Errors.OnlyLinkedAccountCanUnlink());
        delete _accountIdentity[_oldAccount];
        _accounts[_identity].remove(_oldAccount);
        emit AccountUnlinked(_oldAccount, _identity);
    }

    /**
     *  @dev See {IdFactory-getIdentity}.
     */
    function getIdentity(address _account) public view returns (address) {
        return _accountIdentity[_account];
    }

    /**
     *  @dev See {IdFactory-getAccounts}.
     */
    function getAccounts(address _identity) public view returns (address[] memory) {
        return getAccounts(_identity, 0, type(uint256).max);
    }

    /**
     *  @dev See {IdFactory-getAccounts}.
     */
    function getAccounts(address _identity, uint256 _start, uint256 _end) public view returns (address[] memory) {
        return _accounts[_identity].values(_start, _end);
    }

    /**
     *  @dev See {IdFactory-getToken}.
     */
    function getToken(address _identity) public view returns (address) {
        (bool success, bytes32 result,) = LowLevelCall.staticcallReturn64Bytes(
            _identity, abi.encodeWithSelector(IIdentity.getIdentityType.selector)
        );
        return success && uint256(result) == uint256(IdentityTypes.ASSET) ? _accounts[_identity].at(0) : address(0);
    }

    /**
     *  @dev See {IdFactory-isTokenFactory}.
     */
    function isTokenFactory(address _factory) public view returns (bool) {
        return _tokenFactories.contains(_factory);
    }

    /**
     * @dev Links a account to an identity.
     */
    function _linkAccount(address _account, address _identity) internal {
        require(_accountIdentity[_account] == address(0), Errors.AccountAlreadyLinkedToIdentity(_account));
        _accountIdentity[_account] = _identity;
        _accounts[_identity].add(_account);
        emit AccountLinked(_account, _identity);
    }

    // function used to deploy an identity using CREATE3.
    // The deployed address depends only on (address(this), salt), so the same salt yields the
    // same Identity address on every canonical-EVM chain when this factory shares the same address.
    function _deployIdentity(
        string memory _salt,
        uint256 _identityType,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) private returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(IdentityProxy).creationCode, abi.encode(implementationAuthority, _identityType, _keys, _modules)
        );
        return Create3.deploy(0, keccak256(abi.encodePacked(_salt)), bytecode);
    }

}
