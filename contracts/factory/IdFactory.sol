// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { MODULE_TYPE_EXECUTOR, MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import { KeyManager } from "../KeyManager.sol";
import { SmartAccount } from "../SmartAccount.sol";
import { IKeyExecutor } from "../interface/IKeyExecutor.sol";
import { Errors } from "../libraries/Errors.sol";
import { IdentityTypes } from "../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../libraries/KeyPurposes.sol";
import { KeyTypes } from "../libraries/KeyTypes.sol";
import { IdentityProxy } from "../proxy/IdentityProxy.sol";
import { Structs } from "../storage/Structs.sol";
import { IIdFactory } from "./IIdFactory.sol";

contract IdFactory is IIdFactory, Ownable {

    // address of the _implementationAuthority contract making the link to the implementation contract
    address public immutable implementationAuthority;

    /// @notice The KeyApprovalModule singleton auto-installed on every identity at creation.
    /// @dev Provides the ERC-734 `execute`/`approve` ABI via ERC-7579 fallback + executor.
    address public immutable keyApprovalModule;

    mapping(address => bool) private _tokenFactories;

    // as it is not possible to deploy 2 times the same contract address, this mapping allows us to check which
    // salt is taken and which is not
    mapping(string => bool) private _saltTaken;

    // ONCHAINID of the wallet owner
    mapping(address => address) private _userIdentity;

    // wallets currently linked to an ONCHAINID
    mapping(address => address[]) private _wallets;

    // ONCHAINID of the token
    mapping(address => address) private _tokenIdentity;

    // token linked to an ONCHAINID
    mapping(address => address) private _tokenAddress;

    // setting
    constructor(address implementationAuthorityAddress, address keyApprovalModuleAddress) Ownable(msg.sender) {
        require(implementationAuthorityAddress != address(0), Errors.ZeroAddress());
        require(keyApprovalModuleAddress != address(0), Errors.ZeroAddress());
        implementationAuthority = implementationAuthorityAddress;
        keyApprovalModule = keyApprovalModuleAddress;
    }

    /**
     *  @dev See {IdFactory-addTokenFactory}.
     */
    function addTokenFactory(address _factory) external override onlyOwner {
        require(_factory != address(0), Errors.ZeroAddress());
        require(!isTokenFactory(_factory), Errors.AlreadyAFactory(_factory));
        _tokenFactories[_factory] = true;
        emit TokenFactoryAdded(_factory);
    }

    /**
     *  @dev See {IdFactory-removeTokenFactory}.
     */
    function removeTokenFactory(address _factory) external override onlyOwner {
        require(_factory != address(0), Errors.ZeroAddress());
        require(isTokenFactory(_factory), Errors.NotAFactory(_factory));
        _tokenFactories[_factory] = false;
        emit TokenFactoryRemoved(_factory);
    }

    /**
     *  @dev See {IIdFactory-createIdentity}.
     */
    function createIdentity(
        address _wallet,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external override onlyOwner returns (address) {
        require(_wallet != address(0), Errors.ZeroAddress());
        require(keccak256(abi.encode(_salt)) != keccak256(abi.encode("")), Errors.EmptyString());
        string memory oidSalt = string.concat("OID", _salt);
        require(!_saltTaken[oidSalt], Errors.SaltTaken(oidSalt));
        require(_userIdentity[_wallet] == address(0), Errors.WalletAlreadyLinkedToIdentity(_wallet));
        require(_keys.length > 0, Errors.EmptyListOfKeys());

        // Validate at least one management key exists
        bool hasManagementKey = false;
        for (uint256 i = 0; i < _keys.length; i++) {
            if (_keys[i].purpose == KeyPurposes.MANAGEMENT) {
                hasManagementKey = true;
                break;
            }
        }
        require(hasManagementKey, Errors.NoManagementKeyInKeys());

        address identity = _deployIdentity(oidSalt, _identityType);

        // Checks-effects-interactions: commit storage BEFORE any user-controlled `onInstall`
        // runs in `_setupIdentity`. A malicious module re-entering `createIdentity` for the
        // same wallet now hits `_userIdentity[_wallet] != 0` and reverts before a second
        // deployment can occur.
        _saltTaken[oidSalt] = true;
        _userIdentity[_wallet] = identity;
        _wallets[identity].push(_wallet);
        emit WalletLinked(_wallet, identity);

        _setupIdentity(identity, _keys, _modules);

        return identity;
    }

    /**
     *  @dev See {IIdFactory-createTokenIdentity}.
     */
    function createTokenIdentity(
        address _token,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external override returns (address) {
        require(isTokenFactory(msg.sender) || msg.sender == owner(), Ownable.OwnableUnauthorizedAccount(msg.sender));
        require(_token != address(0), Errors.ZeroAddress());
        require(keccak256(abi.encode(_salt)) != keccak256(abi.encode("")), Errors.EmptyString());
        require(_keys.length > 0, Errors.EmptyListOfKeys());
        string memory tokenIdSalt = string.concat("Token", _salt);
        require(!_saltTaken[tokenIdSalt], Errors.SaltTaken(tokenIdSalt));
        require(_tokenIdentity[_token] == address(0), Errors.TokenAlreadyLinked(_token));

        address identity = _deployIdentity(tokenIdSalt, IdentityTypes.ASSET);

        // Checks-effects-interactions: commit storage BEFORE `_setupIdentity` runs user-controlled `onInstall`.
        _saltTaken[tokenIdSalt] = true;
        _tokenIdentity[_token] = identity;
        _tokenAddress[identity] = _token;
        emit TokenLinked(_token, identity);

        _setupIdentity(identity, _keys, _modules);

        return identity;
    }

    /**
     *  @dev See {IdFactory-linkWallet}.
     */
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

    /**
     *  @dev See {IdFactory-unlinkWallet}.
     */
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

    /**
     *  @dev See {IdFactory-getIdentity}.
     */
    function getIdentity(address _wallet) external view override returns (address) {
        if (_tokenIdentity[_wallet] != address(0)) {
            return _tokenIdentity[_wallet];
        }

        return _userIdentity[_wallet];
    }

    /**
     *  @dev See {IdFactory-isSaltTaken}.
     */
    function isSaltTaken(string calldata _salt) external view override returns (bool) {
        return _saltTaken[_salt];
    }

    /**
     *  @dev See {IdFactory-getWallets}.
     */
    function getWallets(address _identity) external view override returns (address[] memory) {
        return _wallets[_identity];
    }

    /**
     *  @dev See {IdFactory-getToken}.
     */
    function getToken(address _identity) external view override returns (address) {
        return _tokenAddress[_identity];
    }

    /**
     *  @dev See {IdFactory-isTokenFactory}.
     */
    function isTokenFactory(address _factory) public view override returns (bool) {
        return _tokenFactories[_factory];
    }

    /// @dev Bootstraps a freshly-deployed identity:
    ///      1. Adds user-supplied keys (factory holds bootstrap MANAGEMENT).
    ///      2. Auto-installs {KeyApprovalModule} so the legacy ERC-734 `execute`/`approve` ABI
    ///         keeps resolving on the identity (option (b) on the IIdentity ABI question).
    ///      3. Installs any caller-supplied modules.
    ///      4. Removes the factory's bootstrap MANAGEMENT key.
    ///
    ///      Module installation goes through {SmartAccount.installModule}, which is
    ///      gated by `onlyManager` — the factory still holds MANAGEMENT at this point. This
    ///      avoids the OZ default `onlyEntryPointOrSelf` chicken-and-egg at deployment time.
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

        // 2. Auto-install the queue module as EXECUTOR (so `executeFromExecutor` accepts it)
        //    and as FALLBACK for the two legacy ERC-734 selectors that previously lived on
        //    the account itself. ERC-7579 fallback initData is `(bytes4 selector ++ payload)`.
        address mod = keyApprovalModule;
        SmartAccount(payable(_identity)).installModule(MODULE_TYPE_EXECUTOR, mod, "");
        SmartAccount(payable(_identity))
            .installModule(MODULE_TYPE_FALLBACK, mod, abi.encodePacked(IKeyExecutor.execute.selector));
        SmartAccount(payable(_identity))
            .installModule(MODULE_TYPE_FALLBACK, mod, abi.encodePacked(IKeyExecutor.approve.selector));
        SmartAccount(payable(_identity))
            .installModule(MODULE_TYPE_FALLBACK, mod, abi.encodePacked(IKeyExecutor.getCurrentNonce.selector));

        // 3. Caller-supplied modules.
        for (uint256 i = 0; i < _modules.length; i++) {
            SmartAccount(payable(_identity))
                .installModule(_modules[i].moduleType, _modules[i].module, _modules[i].initData);
        }

        // 4. Drop the bootstrap key. Direct call: factory still holds MANAGEMENT.
        KeyManager(_identity).removeKey(keccak256(abi.encodePacked(address(this))), KeyPurposes.MANAGEMENT);
    }

    // deploy function with create2 opcode call
    // returns the address of the contract created
    function _deploy(string memory salt, bytes memory bytecode) private returns (address) {
        bytes32 saltBytes = bytes32(keccak256(abi.encodePacked(salt)));
        address addr;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let encoded_data := add(0x20, bytecode) // load initialization code.
            let encoded_size := mload(bytecode) // load init code's length.
            addr := create2(0, encoded_data, encoded_size, saltBytes)
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }
        emit Deployed(addr);
        return addr;
    }

    // function used to deploy an identity using CREATE2
    function _deployIdentity(string memory _salt, uint256 _identityType) private returns (address) {
        bytes memory _code = type(IdentityProxy).creationCode;
        bytes memory _constructData = abi.encode(implementationAuthority, address(this), _identityType);
        bytes memory bytecode = abi.encodePacked(_code, _constructData);
        return _deploy(_salt, bytecode);
    }

}
