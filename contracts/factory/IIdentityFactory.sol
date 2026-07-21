// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

/// @title IIdentityFactory
/// @notice Factory for ONCHAINID identity proxies. Deployment is gated per identity type
///         using an OpenZeppelin AccessManager as the role oracle.
///
///         Admin must register each type up front via {setIdentityTypePolicy}. The policy
///         carries an AM role id (gates {createIdentityFor}) and a `selfDeployable` flag
///         (gates {createIdentity}). Unregistered types revert from both entry points.
///         Use the AM's `PUBLIC_ROLE` for open types; any other role restricts the call to
///         its holders.
///
///         {setIdentityTypePolicy} itself is `restricted` (resolved by the AM).
///
///         Wallets are addressed as ERC-7930 interoperable address envelopes (`bytes`).
///         EVM wallets are wrapped via OZ `InteroperableAddress.formatEvmV1(chainId, addr)`.
///         Non-EVM wallets (Solana, Bitcoin, Stellar, ...) supply the envelope for their
///         own chain; ERC-7913 signers (passkeys, WebAuthn, custom verifiers) are linked
///         the same way once wrapped into an envelope. The registry treats signers and
///         wallets the same; whatever can sign for an identity can also be linked as a
///         wallet on it.
///
///         Proof of control for the wallet being linked depends on the wallet's chain.
///         For EVM and ERC-7913 signers, {linkAccount} runs the signature check on-chain
///         via `SignatureChecker`. For non-EVM wallets, the wallet proves control on its
///         native chain and the proof is relayed through an ERC-7786 cross-chain message;
///         the named identity then calls {confirmCrossChainLink} on this chain. Both
///         halves (wallet control + identity ownership) are required, with one inbound
///         message.
///
///         Bindings are sticky: once linked, a wallet stays bound to that identity, even
///         after revocation. Revocation flips the status to `Revoked` and the wallet can
///         never be relinked to any identity. The wallet -> identity record stays
///         on-chain so compliance modules can resolve historical ownership.
///         Token recovery for tokens still sitting in a revoked wallet is the policy of
///         the compliance / token modules, not this registry; ONCHAINID only guarantees
///         the link is visible and immutable.
///
///         Tokens share the same keyspace as wallets: an ASSET identity's auto-linked
///         wallet is the token, looked up via `getIdentity(bytes)` or
///         `getAccounts(identity)[0]`.
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

    /// @notice Emitted when the policy for a given identity type changes. `roleId == 0`
    ///         means the type is unregistered (both deploy paths revert). `selfDeployable`
    ///         gates {createIdentity}: true allows self-deploy, false reserves the type
    ///         for {createIdentityFor}.
    event IdentityTypePolicySet(uint256 indexed identityType, uint64 indexed roleId, bool selfDeployable);

    /// @notice Emitted when an inbound ERC-7786 message has staged a wallet -> identity
    ///         binding awaiting identity-side confirmation. The link is not active yet.
    event PendingCrossChainLinkProposed(bytes account, address indexed identity, uint256 expiry);

    /// @notice Emitted when an identity confirms a pending cross-chain proposal and the
    ///         wallet becomes active.
    event CrossChainLinkConfirmed(bytes account, address indexed identity);

    /// @notice Emitted when admin adds or removes an authorized ERC-7786 gateway.
    event TrustedGatewaySet(address indexed gateway, bool trusted);

    /// @notice Emitted when the beacon is wired via {setBeacon}.
    event BeaconSet(address indexed beacon);

    /// @notice Wires the UpgradeableBeacon every deployed proxy delegates to. Set-once:
    ///         the beacon can only exist after this factory does (it needs the Identity
    ///         implementation, which needs the enshrined validator, which needs this
    ///         factory's address), so it is wired right after deployment. Restricted.
    function setBeacon(address beaconAddress) external;

    /// @notice Self-deploy. Caller is the account being deployed for and is auto-linked
    ///         as the new identity's first wallet. Gated per type by `selfDeployable`:
    ///         contract-shaped types like ASSET / SMART_CONTRACT opt out because the
    ///         `msg.sender = first wallet` binding does not apply to them. Unregistered
    ///         types revert.
    function createIdentity(
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /// @notice Deploy for an EVM account that cannot sign (a token, a vault). The
    ///         account is auto-linked as the identity's first wallet. Caller must hold
    ///         the role configured for `_identityType` (use `PUBLIC_ROLE` for open types).
    ///         Unregistered types revert.
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys,
        Structs.ModuleInstall[] memory _modules
    ) external returns (address);

    /// @notice Set the per-type policy: AM role required to call {createIdentityFor},
    ///         and whether {createIdentity} (self-deploy) is allowed. Pass `roleId == 0`
    ///         to unregister the type (both deploy paths will revert). `restricted` via
    ///         the AM.
    function setIdentityTypePolicy(uint256 _identityType, uint64 _roleId, bool _selfDeployable) external;

    /// @notice Read the per-type policy. `roleId == 0` means the type is unregistered.
    function getIdentityTypePolicy(uint256 _identityType) external view returns (uint64 roleId, bool selfDeployable);

    /// @notice Link a wallet to the calling identity. The wallet authorizes the link via
    ///         an EIP-712 `LinkAccount` signature. Supports EOAs, ERC-1271 smart wallets,
    ///         and ERC-7913 verifiers (passkeys, etc.) uniformly via `SignatureChecker`.
    ///
    /// @param account ERC-7930 interoperable address envelope. EVM wallets are wrapped
    ///         via OZ `InteroperableAddress.formatEvmV1(chainId, addr)`. Non-EVM wallets
    ///         supply the envelope for their own chain. Malformed envelopes revert.
    /// @param signature EIP-712 signature produced by `account` over
    ///         `LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)`.
    /// @param nonce current nonce for `account` (see {nonceForAccount}).
    /// @param expiry unix timestamp after which the signature is invalid. `expiry == 0`
    ///         reverts. Callers must set freshness explicitly because the binding is
    ///         permanent once consumed.
    function linkAccount(bytes calldata account, bytes calldata signature, uint256 nonce, uint256 expiry) external;

    /// @notice Revoke a wallet from the calling identity. The wallet→identity record
    ///         remains on-chain; status flips to `Revoked`. A revoked wallet can never
    ///         be re-linked (terminal revocation).
    function revokeAccount(bytes calldata account) external;

    /// @notice Confirm a cross-chain link previously proposed via an authenticated
    ///         ERC-7786 message. Caller must be the identity named in the proposal —
    ///         that's the identity-ownership half of the proof. The wallet-control
    ///         half came from the inbound message. After this call the wallet is
    ///         linked with the same sticky-binding rules as any EVM-side link.
    function confirmCrossChainLink(bytes calldata account) external;

    /// @notice Read a pending cross-chain proposal. Returns (address(0), 0) when no
    ///         proposal is staged for `account`.
    function getPendingCrossChainLink(bytes calldata account) external view returns (address identity, uint256 expiry);

    /// @notice Add or remove an authorized ERC-7786 gateway. Inbound messages from any
    ///         non-trusted address are rejected by {receiveMessage}. `restricted` via
    ///         the AM so the trust surface is operated by the same admin role as the
    ///         rest of the factory.
    ///
    ///         Removing a gateway blocks future inbound messages but does not purge
    ///         pending links it already staged. Operators should audit
    ///         {getPendingCrossChainLink} and treat entries proposed via the removed
    ///         gateway as suspect.
    function setTrustedGateway(address gateway, bool trusted) external;

    /// @notice Read whether an address is currently a trusted ERC-7786 gateway.
    function isTrustedGateway(address gateway) external view returns (bool);

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

    /// @notice Enumerate the active wallets currently linked to `identity`. Each entry
    ///         is the ERC-7930 envelope that was used to link the wallet.
    function getAccounts(address identity) external view returns (bytes[] memory);

    /// @notice Paginated variant of {getAccounts}.
    function getAccounts(address identity, uint256 start, uint256 end) external view returns (bytes[] memory);

    /// @notice Returns true iff `identity` was deployed by this factory. Used by
    ///         {linkAccount} to reject pulls into non-OnchainID contracts.
    function isFactoryIdentity(address identity) external view returns (bool);

    /// @notice Current nonce for a signer. Keyed by `keccak256(account)` cast to address
    ///         so EVM and ERC-7913 signers share the same nonce store.
    function nonceForAccount(bytes calldata account) external view returns (uint256);

    /**
     * @dev OZ UpgradeableBeacon every BeaconProxy deployed here delegates to.
     */
    function beacon() external view returns (address);

}
