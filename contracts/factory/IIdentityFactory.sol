// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

/// @title IIdentityFactory
/// @notice Factory for ONCHAINID identity proxies, gated by an OpenZeppelin AccessManager.
///         Access policy is split across two layers:
///           - Per-identity-type creation rights are held in AccessManager roles, with the
///             type→role mapping kept locally via {setIdentityTypeRole}. An unset type
///             defaults to `ADMIN_ROLE` (closed) — new types must be explicitly opened.
///           - Administrative functions ({setIdentityTypeRole}, plus other `restricted`
///             setters) are gated directly through `AccessManaged.restricted` and resolved
///             by the connected AccessManager.
interface IIdentityFactory {

    // event emitted when a wallet is linked to an ONCHAINID contract
    event WalletLinked(address indexed wallet, address indexed identity);

    // event emitted when a token is linked to an ONCHAINID contract
    event TokenLinked(address indexed token, address indexed identity);

    // event emitted when a wallet is unlinked from an ONCHAINID contract
    event WalletUnlinked(address indexed wallet, address indexed identity);

    /// @notice Emitted whenever the AccessManager role required to create a given
    ///         identity type is updated. A `roleId == 0` (admin) means the type is
    ///         closed to non-admin callers.
    event IdentityTypeRoleSet(uint256 indexed identityType, uint64 indexed roleId);

    /**
     *  @dev function used to create a new Identity proxy from the factory.
     *  Authorization model: `msg.sender` must hold the AccessManager role mapped to
     *  `_identityType` via {setIdentityTypeRole}. When no role has been set for the
     *  type, the call is restricted to AccessManager `ADMIN_ROLE` (closed by default).
     *  For `_identityType == IdentityTypes.ASSET` the call additionally writes the
     *  token-linkage mapping; the asset path replaces the legacy `createTokenIdentity`.
     *
     *  @param _subject the wallet (for non-asset types) or token contract address
     *      (for `IdentityTypes.ASSET`) that the new identity is being deployed for.
     *  @param _identityType the type of the identity (see {IdentityTypes}).
     *  @param _salt the salt used by CREATE3 to issue the contract; must be non-empty
     *      and unused on this factory.
     *  @param _keys keys to add to the new identity during bootstrap. Must contain at
     *      least one `MANAGEMENT` key once the factory has dropped its bootstrap key.
     *  @param _modules ERC-7579 modules to install during bootstrap.
     *  @return the address of the deployed identity.
     */
    function createIdentity(
        address _subject,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /**
     *  @dev function used to link a new wallet to an existing identity
     *  @param _newWallet the address of the wallet to link
     *  requires msg.sender to be linked to an existing onchainid
     *  the _newWallet will be linked to the same OID contract as msg.sender
     *  _newWallet cannot be linked to an OID yet
     *  _newWallet cannot be address 0
     *  cannot link more than 100 wallets to an OID, for gas consumption reason
     */
    function linkWallet(address _newWallet) external;

    /**
     *  @dev function used to unlink a wallet from an existing identity
     *  @param _oldWallet the address of the wallet to unlink
     *  requires msg.sender to be linked to the same onchainid as _oldWallet
     *  msg.sender cannot be _oldWallet to keep at least 1 wallet linked to any OID
     *  _oldWallet cannot be address 0
     */
    function unlinkWallet(address _oldWallet) external;

    /// @notice Set (or replace) the AccessManager role required to create identities
    ///         of `_identityType`. Pass `roleId == 0` to force the type back to
    ///         admin-only (closed). Restricted via AccessManager.
    /// @param _identityType the identity type constant (see {IdentityTypes}).
    /// @param _roleId the AccessManager role id callers must hold to create this type.
    function setIdentityTypeRole(uint256 _identityType, uint64 _roleId) external;

    /**
     *  @dev getter for OID contract corresponding to a wallet/token
     *  @param _wallet the wallet/token address
     */
    function getIdentity(address _wallet) external view returns (address);

    /**
     *  @dev getter to fetch the array of wallets linked to an OID contract
     *  @param _identity the address of the OID contract
     *  returns an array of addresses linked to the OID
     */
    function getWallets(address _identity) external view returns (address[] memory);

    /**
     *  @dev getter to fetch the token address linked to an OID contract
     *  @param _identity the address of the OID contract
     *  returns the address linked to the OID
     */
    function getToken(address _identity) external view returns (address);

    /// @notice Returns the AccessManager role required to create identities of
    ///         `_identityType`. Returns `0` (admin-only / closed) for unset types.
    function getIdentityTypeRole(uint256 _identityType) external view returns (uint64);

    /**
     * @dev getter for the implementation authority used by this factory.
     */
    function implementationAuthority() external view returns (address);

}
