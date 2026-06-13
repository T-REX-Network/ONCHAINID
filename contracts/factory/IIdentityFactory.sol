// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

/// @title IIdentityFactory
/// @notice Factory for ONCHAINID identity proxies, gated by an OpenZeppelin AccessManager.
///         Both {createIdentity} and {createIdentityFor} are `restricted`. Admin wires
///         access per selector with `AccessManager.setTargetFunctionRole`.
///
///         Wallets are addressed as `bytes`. EVM addresses pass `abi.encodePacked(addr)`.
///         ERC-7913 signers (passkeys, WebAuthn, custom verifiers) pass their raw signer
///         blob. The registry treats signers and wallets the same; whatever can sign for
///         an identity can also be linked as a wallet on it.
///
///         Bindings are sticky: once linked, a wallet stays bound to that identity.
///         Revocation flips the status to `Revoked` permanently. Tokens share the same
///         keyspace as wallets: an ASSET identity's auto-linked wallet is the token,
///         looked up via `getIdentity(bytes)` or `getAccounts(identity)[0]`.
interface IIdentityFactory {

    /// @notice Lifecycle state of a wallet entry. `None` means "never seen" and is
    ///         distinct from `Revoked` (which keeps the binding on-chain).
    enum AccountStatus {
        None,
        Active,
        Revoked
    }

    // event emitted when a wallet is linked to an identity
    event AccountLinked(bytes account, address indexed identity);

    // event emitted when a wallet is revoked from its identity (binding stays on-chain, status flips)
    event AccountRevoked(bytes account, address indexed identity);

    // event emitted when a token is linked to an ONCHAINID contract (tokens are EVM-only)
    event TokenLinked(address indexed token, address indexed identity);

    /// @notice Self-deploy. Caller is the account being deployed for and is auto-linked
    ///         as the new identity's first wallet. Gated by the AccessManager.
    function createIdentity(
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /// @notice Deploy for an EVM account that cannot sign (a token, a vault). The
    ///         account is auto-linked as the identity's first wallet. Gated by the
    ///         AccessManager.
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /// @notice Link a wallet (signer bytes) to the calling identity. The wallet
    ///         authorizes the link via an EIP-712 `LinkAccount` signature. Supports
    ///         EOAs, ERC-1271 smart wallets, and ERC-7913 verifiers (passkeys, etc.)
    ///         uniformly via `SignatureChecker`.
    ///
    /// @param account signer bytes. `abi.encodePacked(address)` for EOAs and ERC-1271
    ///         smart wallets, raw ERC-7913 signer blob for passkeys / custom verifiers.
    /// @param signature EIP-712 signature produced by `account` over
    ///         `LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)`.
    /// @param nonce current nonce for `account` (see {noncesForAccount}).
    /// @param expiry unix timestamp after which the signature is invalid. `expiry == 0`
    ///         reverts. Callers must set freshness explicitly because the binding is
    ///         permanent once consumed.
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external;

    /// @notice Revoke a wallet from the calling identity. The wallet→identity record
    ///         remains on-chain; status flips to `Revoked`. A revoked wallet can never
    ///         be re-linked (terminal revocation).
    function revokeAccount(bytes calldata account) external;

    /// @notice Resolve a wallet to its bound identity. Returns `address(0)` when the
    ///         wallet's status is not `Active` (never linked, or revoked).
    function getIdentity(bytes calldata account) external view returns (address);

    /// @notice Same as {getIdentity}, but also returns the wallet's current lifecycle
    ///         status. Distinguishes "never linked" from "revoked".
    function getIdentityIncludingRevoked(bytes calldata account)
        external
        view
        returns (address identity, AccountStatus status);

    /// @notice Read the current lifecycle status of a wallet entry.
    function getAccountStatus(bytes calldata account) external view returns (AccountStatus);

    /// @notice Enumerate the active wallets currently linked to `identity`.
    function getAccounts(address identity) external view returns (bytes[] memory);

    /// @notice Paginated variant of {getAccounts}.
    function getAccounts(address identity, uint256 start, uint256 end) external view returns (bytes[] memory);

    /// @notice Returns true iff `identity` was deployed by this factory. Used by
    ///         {linkAccount} to reject pulls into non-OnchainID contracts.
    function isFactoryIdentity(address identity) external view returns (bool);

    /// @notice Current nonce for a signer. Keyed by `keccak256(account)` cast to address
    ///         so EVM and ERC-7913 signers share the same nonce store.
    function noncesForAccount(bytes calldata account) external view returns (uint256);

    /**
     * @dev OZ UpgradeableBeacon every BeaconProxy deployed here delegates to.
     */
    function beacon() external view returns (address);

}
