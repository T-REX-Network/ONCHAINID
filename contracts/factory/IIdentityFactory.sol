// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

/// @title IIdentityFactory
/// @notice Factory for ONCHAINID identity proxies, gated by an OpenZeppelin AccessManager.
///         Access policy is split across two layers:
///           - Per-identity-type creation rights are held in AccessManager roles, with the
///             type→role mapping kept locally via {setIdentityTypeRole}. An unset type
///             defaults to `ADMIN_ROLE` (closed) — new types must be explicitly opened.
///           - Administrative functions ({setIdentityTypeRole}, {setCanDeployFor}) are
///             gated directly through `AccessManaged.restricted` and resolved by the
///             connected AccessManager.
///
///         There are three deploy paths, one per consent model:
///           1. {createIdentity} — `msg.sender` deploys for themselves. The act of calling
///              IS the consent; no signature required.
///           2. {createIdentityWithSignature} — a sponsor deploys on behalf of an account
///              that produced an EIP-712 authorization. Account is `bytes`, so EOAs,
///              ERC-1271 smart wallets, and ERC-7913 verifiers (passkeys, WebAuthn, RSA, etc.)
///              are all supported through OpenZeppelin's `SignatureChecker`.
///           3. {createIdentityFor} — a role-holder deploys for an EVM account that cannot
///              produce a signature (e.g. a token contract represented as an asset
///              identity). The per-type AccessManager role IS the consent; the type must
///              also be explicitly enabled via {setCanDeployFor}.
///
///         Wallets are addressed as `bytes`. EVM-shaped wallets pass `abi.encodePacked(addr)`
///         (20 bytes). ERC-7913 signers (passkeys, WebAuthn, custom verifiers) pass their
///         raw signer blob — the same bytes `SignatureChecker` accepts. The registry treats
///         these uniformly: whatever can sign for an identity can also be linked as a
///         wallet on that identity. There is no separate "signer vs wallet" concept.
///
///         Bindings are permanent (sticky): once linked, a wallet can never be linked to a
///         different identity. Revocation flips the wallet's status to `Revoked` (terminal —
///         the wallet can never be re-linked) but never clears the underlying record. Token
///         addresses are resolved separately via {getToken} / {getTokenIdentity}.
///
///         Cross-chain wallet linking (distinguishing the same address on different chains
///         via ERC-7930 envelopes, ERC-7786 receiver for cross-chain proofs) is a follow-up.
interface IIdentityFactory {

    /// @notice Lifecycle state of a wallet entry. `None` distinguishes "never seen" from
    ///         the post-revocation state (which keeps `_userIdentity` populated).
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

    /// @notice Emitted whenever the AccessManager role required to create a given
    ///         identity type is updated. A `roleId == 0` (admin) means the type is
    ///         closed to non-admin callers.
    event IdentityTypeRoleSet(uint256 indexed identityType, uint64 indexed roleId);

    /// @notice Emitted when the "can deploy for someone else" flag is flipped for an
    ///         identity type. When true, {createIdentityFor} accepts that type; otherwise
    ///         only {createIdentity} / {createIdentityWithSignature} are valid for it.
    event CanDeployForSet(uint256 indexed identityType, bool allowed);

    /// @notice Self-deploy: caller is also the account being deployed for. The call
    ///         itself IS the consent. `msg.sender` is auto-linked as the new identity's
    ///         first wallet (stored as `abi.encodePacked(msg.sender)`).
    ///
    ///         `msg.sender` must hold the AccessManager role mapped to `_identityType`
    ///         via {setIdentityTypeRole}.
    function createIdentity(
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /// @notice Sponsored deploy: `msg.sender` is a relayer / KYC provider / paymaster.
    ///         `_account` is the signer bytes that authorized this exact deployment via
    ///         EIP-712. Supports EOAs (20-byte address), ERC-1271 smart wallets (20-byte
    ///         contract address), and ERC-7913 verifiers (verifier address + key data,
    ///         e.g. WebAuthn passkeys) uniformly through `SignatureChecker`.
    ///
    ///         Per-type AccessManager role check applies to `msg.sender` (the sponsor).
    ///         Consent for `_account` comes from the signature. `_account` is also
    ///         auto-linked as the new identity's first wallet — passkeys and other
    ///         non-EVM signers become first-class registry entries on the same footing
    ///         as EOAs.
    function createIdentityWithSignature(
        bytes calldata _account,
        uint256 _identityType,
        string calldata _salt,
        Structs.KeyParam[] calldata _keys,
        Structs.ModuleInstall[] calldata _modules,
        uint256 _nonce,
        uint256 _expiry,
        bytes calldata _signature
    ) external returns (address);

    /// @notice Role-gated deploy for an EVM account that cannot sign — typically a token
    ///         contract being given an asset identity, or any other smart contract whose
    ///         owner role is on the calling factory (e.g. T-REX `TokenFactory`).
    ///
    ///         Two-layer authorization:
    ///           - `msg.sender` must hold the per-type AccessManager role for `_identityType`.
    ///           - `_identityType` must be enabled in the {canDeployFor} allowlist.
    ///
    ///         The account is auto-linked as the identity's first wallet, stored as
    ///         `abi.encodePacked(_account)`.
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
    /// @param account signer bytes — `abi.encodePacked(address)` for EOAs and ERC-1271
    ///         smart wallets, raw ERC-7913 signer blob for passkeys / custom verifiers.
    /// @param signature EIP-712 signature produced by `account` over
    ///         `LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)`.
    /// @param nonce current nonce for `account` (see {noncesForAccount}).
    /// @param expiry unix timestamp after which the signature is invalid. `expiry == 0`
    ///         reverts — callers must set freshness explicitly because the binding is
    ///         permanent once consumed.
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external;

    /// @notice Revoke a wallet from the calling identity. The wallet→identity record
    ///         remains on-chain; status flips to `Revoked`. A revoked wallet can never
    ///         be re-linked (terminal revocation).
    function revokeAccount(bytes calldata account) external;

    /// @notice Set (or replace) the AccessManager role required to create identities
    ///         of `_identityType`. Pass `roleId == 0` to force the type back to
    ///         admin-only (closed). Restricted via AccessManager.
    function setIdentityTypeRole(uint256 _identityType, uint64 _roleId) external;

    /// @notice Enable or disable the {createIdentityFor} path for `_identityType`.
    function setCanDeployFor(uint256 _identityType, bool _allowed) external;

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

    /// @notice Token address linked to an identity (tokens are EVM-only).
    function getToken(address _identity) external view returns (address);

    /// @notice Forward lookup for tokens: resolve a token address to the identity that
    ///         represents it. Returns `address(0)` if the token has no identity in this
    ///         registry. Tokens live in a dedicated keyspace, separate from wallets.
    function getTokenIdentity(address token) external view returns (address);

    /// @notice Returns the AccessManager role required to create identities of
    ///         `_identityType`. Returns `0` (admin-only / closed) for unset types.
    function getIdentityTypeRole(uint256 _identityType) external view returns (uint64);

    /// @notice Returns true iff {createIdentityFor} accepts `_identityType`. Off by
    ///         default; admin enables per-type via {setCanDeployFor}.
    function canDeployFor(uint256 _identityType) external view returns (bool);

    /// @notice Returns true iff `identity` was deployed by this factory. Used by
    ///         {linkAccount} to reject pulls into non-OnchainID contracts.
    function isFactoryIdentity(address identity) external view returns (bool);

    /// @notice Current nonce for a signer. Keyed by `keccak256(account)` cast to address
    ///         so EVM and ERC-7913 signers share the same nonce store.
    function noncesForAccount(bytes calldata account) external view returns (uint256);

    /**
     * @dev getter for the implementation authority used by this factory.
     */
    function implementationAuthority() external view returns (address);

}
