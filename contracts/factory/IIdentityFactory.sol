// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
///         Admin also registers the modules each type deploys with, via
///         {setIdentityTypeModules}. Callers pass no modules, so the admin decides which
///         code runs on an identity and with which purpose.
///
///         Both setters are `restricted` (resolved by the AM).
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
///         the named identity then calls {settlePendingCrossChainLink} on this chain. Both
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
///         `getAccounts(identity, 0, 1)[0]`.
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

    /// @notice Emitted when the policy for a given identity type is set. Setting a policy
    ///         registers the type. `selfDeployable` gates {createIdentity}: true allows
    ///         self-deploy, false reserves the type for {createIdentityFor}. `singleBinding`
    ///         marks types bound to one contract (ASSET, SMART_CONTRACT): they keep the
    ///         account set at deploy and can never link or revoke another.
    event IdentityTypePolicySet(
        uint256 indexed identityType, uint64 indexed roleId, bool selfDeployable, bool singleBinding
    );

    /// @notice Emitted when an identity type is unregistered (both deploy paths revert).
    event IdentityTypePolicyRemoved(uint256 indexed identityType);

    /// @notice Emitted when the modules registered for an identity type change. Every
    ///         identity of that type installs these from then on.
    event IdentityTypeModulesSet(uint256 indexed identityType, Structs.ModuleInstall[] modules);

    /// @notice Emitted when an inbound ERC-7786 message has staged a wallet -> identity
    ///         binding awaiting identity-side confirmation. The link is not active yet.
    event PendingCrossChainLinkProposed(bytes account, address indexed identity, uint256 expiry, address gateway);

    /// @notice Emitted when an identity confirms a pending cross-chain proposal and the
    ///         wallet becomes active.
    event CrossChainLinkConfirmed(bytes account, address indexed identity);

    /// @notice Emitted when an identity declines a pending cross-chain proposal. The
    ///         proposal is deleted and no binding is created; the wallet stays unlinked
    ///         and can be proposed again later.
    event CrossChainLinkRejected(bytes account, address indexed identity, uint256 expiry);

    /// @notice Emitted when admin adds or removes an authorized ERC-7786 gateway
    ///         for one origin chain.
    event TrustedGatewaySet(address indexed gateway, bytes2 chainType, bytes chainReference, bool trusted);

    /// @notice Emitted when admin adds or removes an approved ERC-7913 verifier.
    event TrustedVerifierSet(address indexed verifier, bool trusted);

    /// @notice Emitted when the beacon is deployed via {initializeBeacon}.
    event BeaconInitialized(address indexed implementation);

    /// @notice Emitted when the beacon implementation is upgraded via {upgradeBeacon}.
    event BeaconUpgraded(address indexed implementation);

    /// @notice One-shot bootstrap: deploys the OZ UpgradeableBeacon at the factory's
    ///         predetermined CREATE3 slot ({beacon}), pointing at `implementation` and
    ///         owned by the factory itself. Needed because the beacon can only exist
    ///         after this factory does (it needs the Identity implementation, which needs
    ///         the enshrined validator, which needs this factory's address). Restricted.
    function initializeBeacon(address implementation) external;

    /// @notice Upgrade the implementation every deployed identity delegates to. The factory
    ///         owns the beacon, so this is the only upgrade path, and it is gated by the
    ///         factory's current authority. The candidate must name this factory, keep the
    ///         registry module the outgoing implementation names, have its initializers
    ///         disabled, and report `expectedVersion` from {Identity.version}, so a build
    ///         that forgot the version bump is rejected. Restricted.
    function upgradeBeacon(address newImplementation, string calldata expectedVersion) external;

    /// @notice Self-deploy. Caller is the account being deployed for and is auto-linked
    ///         as the new identity's first wallet. Gated per type by `selfDeployable`:
    ///         contract-shaped types like ASSET / SMART_CONTRACT opt out because the
    ///         `msg.sender = first wallet` binding does not apply to them. Unregistered
    ///         types revert.
    ///         The modules registered for the type are installed. Callers do not pick them.
    function createIdentity(uint256 _identityType, string memory _salt, Structs.KeyParam[] memory _keys)
        external
        returns (address);

    /// @notice Deploy for another EVM account. The account is auto-linked as the
    ///         identity's first wallet. Caller must hold the role configured for
    ///         `_identityType`. Unregistered types revert.
    ///
    ///         `_account` signs nothing, so an issuer can onboard a wallet without asking
    ///         its owner for anything. The deploy instead only succeeds if `_account` ends
    ///         up as the only wallet with MANAGEMENT on the new identity, so the identity is
    ///         managed by the wallet it was created for and never by the caller. The type's
    ///         registered modules may hold MANAGEMENT too, but callers do not choose modules,
    ///         so a caller cannot act through one either. Single binding types (ASSET,
    ///         SMART_CONTRACT) hold no key, so they skip the check and rely on the caller's
    ///         role, which must not be `PUBLIC_ROLE`.
    function createIdentityFor(
        address _account,
        uint256 _identityType,
        string memory _salt,
        Structs.KeyParam[] memory _keys
    ) external returns (address);

    /// @notice Set the per-type policy: AM role required to call {createIdentityFor},
    ///         whether {createIdentity} (self-deploy) is allowed, and whether the type is
    ///         single-binding. Pass `_singleBinding = true` for types bound to one contract
    ///         (ASSET, SMART_CONTRACT, ...): they keep the account set at deploy and can
    ///         never link or revoke another. Setting a policy registers the type;
    ///         registration is tracked separately from the role, so the AM's `ADMIN_ROLE`
    ///         (id 0) is usable like any other role. `restricted` via the AM.
    function setIdentityTypePolicy(uint256 _identityType, uint64 _roleId, bool _selfDeployable, bool _singleBinding)
        external;

    /// @notice Unregister an identity type (both deploy paths will revert). `restricted`
    ///         via the AM.
    function removeIdentityTypePolicy(uint256 _identityType) external;

    /// @notice Read the per-type policy. `registered == false` means the type is
    ///         unregistered and both deploy paths revert.
    function getIdentityTypePolicy(uint256 _identityType)
        external
        view
        returns (uint64 roleId, bool selfDeployable, bool singleBinding, bool registered);

    /// @notice Set the modules installed on every identity of `_identityType`, replacing
    ///         any list set before. Deploy callers pass no modules, so this is the only way
    ///         a module reaches an identity, and the admin decides which code runs with
    ///         which purpose. A type with no modules registered cannot deploy, because
    ///         `Identity.initialize` needs a validator or an executor. `restricted`.
    function setIdentityTypeModules(uint256 _identityType, Structs.ModuleInstall[] calldata _modules) external;

    /// @notice Read the modules registered for an identity type.
    function getIdentityTypeModules(uint256 _identityType) external view returns (Structs.ModuleInstall[] memory);

    /// @notice Link a wallet to the calling identity. The wallet authorizes the link via
    ///         an EIP-712 `LinkAccount` signature. Supports EOAs, ERC-1271 smart wallets,
    ///         and ERC-7913 verifiers (passkeys, etc.) uniformly via `SignatureChecker`.
    ///         ERC-7913 signers only link when their verifier is approved via
    ///         {setTrustedVerifier}.
    ///
    /// @param account ERC-7930 interoperable address envelope. EVM wallets are wrapped
    ///         via OZ `InteroperableAddress.formatEvmV1(chainId, addr)`. The chain type
    ///         must be eip-155 and the chain reference must be the local chain id in
    ///         minimal big-endian form: the signature check cannot prove control on any
    ///         other chain, so envelopes for non-EVM or foreign EVM chains revert and
    ///         go through {settlePendingCrossChainLink} instead. Malformed envelopes revert.
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
    ///
    ///         Revoking the identity's last wallet only retires that address: wallet
    ///         links and ERC-734 keys are separate namespaces, so the identity's keys
    ///         are untouched and a MANAGEMENT key can still drive {linkAccount} to bind
    ///         a fresh wallet. Integrators must not treat an identity whose active set
    ///         is momentarily empty as dead.
    function revokeAccount(bytes calldata account) external;

    /// @notice Settle a cross-chain link previously proposed via an authenticated
    ///         ERC-7786 message. Caller must be the identity named in the proposal —
    ///         that's the identity-ownership half of the proof. The wallet-control
    ///         half came from the inbound message.
    ///
    ///         Either way the proposal is deleted, so an identity that declines (or
    ///         never got around to accepting) does not leave a dead entry behind.
    ///
    /// @param account the wallet envelope carried in the proposal.
    /// @param accept `true` links the wallet, with the same sticky-binding rules as
    ///         any EVM-side link; reverts if the proposal has expired. `false`
    ///         declines and clears the proposal, allowed at any time including after
    ///         expiry. Declining creates no binding, so the wallet stays unlinked and
    ///         may be proposed again later.
    function settlePendingCrossChainLink(bytes calldata account, bool accept) external;

    /// @notice Read a pending cross-chain proposal. Returns (address(0), 0) when no
    ///         proposal is staged for `account`.
    function getPendingCrossChainLink(bytes calldata account) external view returns (address identity, uint256 expiry);

    /// @notice Add or remove an authorized ERC-7786 gateway for one origin chain.
    ///         The origin is the ERC-7930 (chainType, chainReference) pair. A gateway
    ///         serving several origins needs one entry per origin; messages from any
    ///         other origin are rejected by {receiveMessage}. `restricted` via the AM
    ///         so the trust surface is operated by the same admin role as the rest of
    ///         the factory.
    ///
    ///         Removing an entry blocks future inbound messages but does not purge
    ///         pending links it already staged. Operators should audit
    ///         {getPendingCrossChainLink} and treat entries proposed via the removed
    ///         gateway as suspect; the named identity clears one by calling
    ///         {settlePendingCrossChainLink} with `accept = false`.
    function setTrustedGateway(address gateway, bytes2 chainType, bytes calldata chainReference, bool trusted) external;

    /// @notice Read whether a gateway is currently trusted for one origin chain.
    function isTrustedGateway(address gateway, bytes2 chainType, bytes calldata chainReference)
        external
        view
        returns (bool);

    /// @notice Add or remove an approved ERC-7913 verifier. {linkAccount} rejects
    ///         signers longer than 20 bytes whose leading verifier is not listed,
    ///         because the verifier judges its own signer's proof. `restricted` via
    ///         the AM.
    ///
    ///         Listing a verifier means trusting its code to judge proof of
    ///         control. A permissive or buggy verifier lets any signer that names
    ///         it link without a genuine proof, so grant the role for this
    ///         function only to admins who vet verifier implementations.
    function setTrustedVerifier(address verifier, bool trusted) external;

    /// @notice Read whether an address is currently an approved ERC-7913 verifier.
    function isTrustedVerifier(address verifier) external view returns (bool);

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

    /// @notice Enumerate the active wallets currently linked to `identity`, paginated
    ///         over `[start, end)` (out-of-range bounds are clamped). Each entry is the
    ///         ERC-7930 envelope that was used to link the wallet. Envelopes are
    ///         unbounded bytes and the set has no size cap, so read in pages sized to
    ///         the provider's eth_call gas cap; {getAccountsCount} gives the total.
    function getAccounts(address identity, uint256 start, uint256 end) external view returns (bytes[] memory);

    /// @notice Number of active wallets currently linked to `identity`.
    function getAccountsCount(address identity) external view returns (uint256);

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
