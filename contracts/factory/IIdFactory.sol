// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

interface IIdFactory {

    /// events
    // event emitted whenever a single contract is deployed by the factory
    event Deployed(address indexed _addr);

    // event emitted when a account is linked to an ONCHAINID contract
    event AccountLinked(address indexed account, address indexed identity);

    // event emitted when a account is unlinked from an ONCHAINID contract
    event AccountUnlinked(address indexed account, address indexed identity);

    // event emitted when an address is registered on the factory as a Token
    // factory address, granting this address the privilege to issue
    // Onchain identities for tokens
    event TokenFactoryAdded(address indexed factory);

    // event emitted when a previously recorded token factory address is removed
    event TokenFactoryRemoved(address indexed factory);

    /// functions

    /**
     *  @dev function used to create a new Identity proxy from the factory. Single entry point
     *       for both user and token identities; the `_identityType` parameter selects the kind.
     *
     *       When `_identityType == IdentityTypes.ASSET`, the call may be made by a registered
     *       token factory or by the owner, the salt is namespaced under `"Token"`, and
     *       `getToken(identity)` will return `_account`. For any other identity type, only the
     *       owner may call, the salt is namespaced under `"OID"`, and `getToken` returns 0.
     *
     *  @param _account the address bound to the identity (a user wallet, or a token contract for asset identities)
     *  @param _identityType the type of the identity (see IdentityTypes library)
     *  @param _salt the salt used by CREATE3 to issue the contract (namespaced internally per identity kind)
     *  @param _keys the list of keys to add to the identity (must contain at least one MANAGEMENT key)
     *  @param _modules the ERC-7579 modules to install during creation
     *  requires a new salt within the relevant namespace for each deployment
     *  _account cannot already be linked to an ONCHAINID
     */
    function createIdentity(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /**
     *  @dev function used to link a new account to an existing identity
     *  @param _newAccount the address of the account to link
     *  requires msg.sender to be linked to an existing onchainid
     *  the _newAccount will be linked to the same OID contract as msg.sender
     *  _newAccount cannot be linked to an OID yet
     *  _newAccount cannot be address 0
     */
    function linkAccount(address _newAccount) external;

    /**
     *  @dev function used to unlink a account from an existing identity
     *  @param _oldAccount the address of the account to unlink
     *  requires msg.sender to be linked to the same onchainid as _oldAccount
     *  msg.sender cannot be _oldAccount to keep at least 1 account linked to any OID
     *  _oldAccount cannot be address 0
     */
    function unlinkAccount(address _oldAccount) external;

    /**
     *  @dev function used to register an address as a token factory
     *  @param _factory the address of the token factory
     *  can be called only by Owner
     *  _factory cannot be registered yet
     *  once the factory has been registered it can deploy token identities
     */
    function addTokenFactory(address _factory) external;

    /**
     *  @dev function used to unregister an address previously registered as a token factory
     *  @param _factory the address of the token factory
     *  can be called only by Owner
     *  _factory has to be registered previously
     *  once the factory has been unregistered it cannot deploy token identities anymore
     */
    function removeTokenFactory(address _factory) external;

    /**
     *  @dev getter for OID contract corresponding to a account/token
     *  @param _account the account/token address
     */
    function getIdentity(address _account) external view returns (address);

    /**
     *  @dev getter to fetch the array of accounts linked to an OID contract
     *  @param _identity the address of the OID contract
     *  returns an array of addresses linked to the OID
     */
    function getAccounts(address _identity) external view returns (address[] memory);

    /**
     *  @dev getter to fetch the array of accounts linked to an OID contract
     *  @param _identity the address of the OID contract
     *  @param _start the start index of the array
     *  @param _end the end index of the array
     *  returns an array of addresses linked to the OID
     */
    function getAccounts(address _identity, uint256 _start, uint256 _end) external view returns (address[] memory);

    /**
     *  @dev getter to fetch the token address linked to an OID contract
     *  @param _identity the address of the OID contract
     *  returns the address linked to the OID
     */
    function getToken(address _identity) external view returns (address);

    /**
     *  @dev getter to know if an address is registered as token factory or not
     *  @param _factory the address of the factory
     *  returns true if the address corresponds to a registered factory
     */
    function isTokenFactory(address _factory) external view returns (bool);

    /**
     * @dev getter for the implementation authority used by this factory.
     */
    function implementationAuthority() external view returns (address);

}
