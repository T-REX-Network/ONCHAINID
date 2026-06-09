// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { IIdentity } from "../interface/IIdentity.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { IdentityProxy } from "../proxy/IdentityProxy.sol";
import { Structs } from "../storage/Structs.sol";
import { Create3 } from "../vendor/utils/Create3.sol";
import { IIdFactory } from "./IIdFactory.sol";

contract IdFactory is IIdFactory, Ownable {

    using EnumerableSet for EnumerableSet.AddressSet;

    // address of the _implementationAuthority contract making the link to the implementation contract
    address public immutable implementationAuthority;

    EnumerableSet.AddressSet private _tokenFactories;

    // ONCHAINID of any address bound to it (account wallet or token contract)
    mapping(address => address) private _accountIdentity;

    // addresses currently linked to an ONCHAINID (single-entry for token identities)
    mapping(address => EnumerableSet.AddressSet) private _accounts;

    constructor(address implementationAuthorityAddress, address owner) Ownable(owner) {
        require(implementationAuthorityAddress != address(0), Errors.ZeroAddress());
        implementationAuthority = implementationAuthorityAddress;
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
            _msgSender() == owner() || (isAsset && isTokenFactory(_msgSender())),
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
        address identity = _deployIdentity(prefixedSalt, _identityType, keys, _modules);

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
        try IIdentity(_identity).getIdentityType() returns (uint256 result) {
            if (result == uint256(IdentityTypes.ASSET)) {
                return _accounts[_identity].at(0);
            }
        } catch { }
        return address(0);
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
