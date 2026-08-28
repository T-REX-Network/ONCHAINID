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

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import { IIdentityFactory } from "../../factory/IIdentityFactory.sol";
import { IClaimIssuer } from "../../interface/IClaimIssuer.sol";
import { IIdentity } from "../../interface/IIdentity.sol";
import { Errors } from "../../libraries/Errors.sol";
import { Structs } from "../../storage/Structs.sol";
import { Attestation, IEAS } from "../../vendor/eas/IEAS.sol";

/**
 * @title EASClaimIssuer
 * @notice A `ClaimIssuer` that reads EAS attestations live. It stores no claim state.
 *         Revocation, expiry, and wallet unlinking all take effect on the next call.
 *
 * @dev    ERC-3643 asks a `ClaimIssuer` if a claim is valid. EAS is a general
 *         attestation layer that speaks a different vocabulary (schema UIDs). This
 *         adapter translates: a KYC provider already attesting on EAS does not have
 *         to re-issue the same fact as an OnchainID claim.
 *
 *         Trust: EAS for everything `getAttestation` returns; the factory for the
 *         identity/wallet lookups; the AM admin for the topic-to-schema map and the
 *         per-topic attester allowlist. Both EAS and factory addresses are immutable so
 *         the admin cannot silently repoint them.
 *
 *         An attestation may name the identity itself (identities are ERC-7579 smart
 *         accounts) or a wallet linked to the identity in `IdentityFactory`. The
 *         wallet's factory status is intentionally ignored: the attestation belongs
 *         to the identity, and requiring `Active` would deadlock recovery on a
 *         compromised wallet. Kills happen elsewhere: attester revokes on EAS, holder
 *         removes the local record via `removeClaim`. This adapter has no EIP-712 domain,
 *         so the registry has no digest to revoke on removal and skips that step. Re-adding
 *         is still blocked by EAS, which is re-read on every call.
 *
 *         The `IClaimIssuer` `signature` field carries the EAS attestation UID as a
 *         bare 32-byte word (`abi.encodePacked(uid)`). Length-32 check rejects any
 *         other shape.
 *
 *         The `ClaimData` envelope must mirror the attestation: `issuedAt` is the
 *         attestation `time`, `validUntil` its `expirationTime`, `payload` its `data`.
 *         The ERC-735 registry stores that envelope verbatim, so binding it here is what
 *         keeps the stored record equal to what the attester actually signed rather than
 *         a fabrication sitting next to a genuine UID. Callers build the envelope from
 *         `getAttestationData` plus the attestation's own timestamps.
 *
 *         Not supported: off-chain EAS attestations, non-EVM wallets, cross-chain
 *         reads. Any `IIdentity` / ERC-734 / ERC-735 method that has no meaning on a
 *         stateless reader reverts with `Errors.EASNotSupported`.
 */
contract EASClaimIssuer is IClaimIssuer, AccessManaged {

    /// @dev EAS deployment on this chain. Immutable so the admin cannot silently repoint
    ///      at a fake EAS and bypass revocation. Redeploy the adapter to change.
    ///      Read via {getEAS}.
    IEAS private immutable _EAS;

    /// @dev `IdentityFactory` used to resolve wallets to identities and to gate the
    ///      self-recipient branch. Immutable for the same reason as `_EAS`.
    ///      Read via {getFactory}.
    IIdentityFactory private immutable _FACTORY;

    /// @dev Topic to EAS schema UID map. The token side asks about a `uint256` topic,
    ///      EAS speaks in `bytes32` schema UIDs, this is the dictionary between them.
    ///      Unset (`bytes32(0)`) means the topic is not configured; `_resolve` returns
    ///      `NotIssued` for it. Setting a topic to zero is the intended kill switch.
    ///      Used twice in `_resolve`: first to reject unmapped topics, then to require
    ///      the attestation's own `schema` field to equal the mapped value, so an
    ///      attestation made under one topic's schema cannot be replayed against
    ///      another. The attester allowlist closes the other half of that gap by being
    ///      keyed per topic. Read via {getSchemaForTopic}.
    mapping(uint256 topic => bytes32 schema) private _schemaOf;

    /// @dev Attesters this adapter accepts, per topic. Any `address` can write an
    ///      attestation on EAS; only those listed for the queried topic are treated as
    ///      trusted issuers here. Scoped per topic like `trustedIssuersRegistry` on the
    ///      OnchainID side, so trusting an attester for one topic does not authorize it
    ///      for the rest. Read via {getIsAttesterAllowed}.
    mapping(uint256 topic => mapping(address attester => bool allowed)) private _isAttesterAllowed;

    /// @dev Adapter initialized. Emits the immutable EAS and factory addresses so
    ///      indexers can catalog every deployed adapter with a single topic scan.
    event AdapterInitialized(address indexed eas, address indexed factory);

    /// @dev Schema binding changed. `schema == 0` means the topic was unbound.
    event SchemaForTopicSet(uint256 indexed topic, bytes32 indexed schema);

    /// @dev Attester allowlist changed for one topic. Monitor `allowed == true` events:
    ///      they widen the trust surface.
    event AttesterSet(uint256 indexed topic, address indexed attester, bool allowed);

    /**
     * @param authority_ AccessManager instance backing `restricted` setters.
     * @param eas_ The EAS core contract on this chain.
     * @param factory_ The IdentityFactory (global registry).
     */
    constructor(address authority_, IEAS eas_, IIdentityFactory factory_) AccessManaged(authority_) {
        require(address(eas_) != address(0), Errors.ZeroAddress());
        require(address(factory_) != address(0), Errors.ZeroAddress());
        _EAS = eas_;
        _FACTORY = factory_;
        emit AdapterInitialized(address(eas_), address(factory_));
    }

    /// @notice Bind an ERC-3643 topic to an EAS schema UID. Pass `schema = 0` to unbind
    ///         (kill switch for a compromised schema, no redeploy needed).
    function setSchemaForTopic(uint256 topic, bytes32 schema) external restricted {
        _schemaOf[topic] = schema;
        emit SchemaForTopicSet(topic, schema);
    }

    /// @notice Add or remove an attester from the accepted set for one topic. Adding
    ///         widens the trust surface: attestations from `attester` under the schema
    ///         bound to `topic` will pass. Other topics are unaffected.
    /// @dev    Rejects `address(0)`: a deployment-script bug passing an unset address
    ///         would otherwise succeed silently, leaving the real attester unlisted.
    function setAttester(uint256 topic, address attester, bool allowed) external restricted {
        require(attester != address(0), Errors.ZeroAddress());
        _isAttesterAllowed[topic][attester] = allowed;
        emit AttesterSet(topic, attester, allowed);
    }

    /// @notice EAS core contract this adapter reads from.
    function getEAS() public view returns (IEAS) {
        return _EAS;
    }

    /// @notice `IdentityFactory` this adapter delegates identity and wallet lookups to.
    function getFactory() public view returns (IIdentityFactory) {
        return _FACTORY;
    }

    /// @notice EAS schema UID bound to `topic`, or `bytes32(0)` if unbound.
    function getSchemaForTopic(uint256 topic) public view returns (bytes32) {
        return _schemaOf[topic];
    }

    /// @notice Whether `attester` is in the accepted set for `topic`.
    function getIsAttesterAllowed(uint256 topic, address attester) public view returns (bool) {
        return _isAttesterAllowed[topic][attester];
    }

    /// @notice Raw read only — returns the payload even for revoked, expired, or
    ///         untrusted attestations. Always pair with `isClaimValid` (or
    ///         `getClaimStatus`) before making eligibility or display decisions.
    /// @dev    Returns empty bytes if `sig` is not a 32-byte UID or the attestation does
    ///         not exist. Does not check schema, attester, revocation, or expiry. A
    ///         front-end that renders this payload without calling `isClaimValid` will
    ///         show stale data for attestations revoked on EAS.
    function getAttestationData(bytes calldata sig) external view returns (bytes memory) {
        if (sig.length != 32) return "";
        bytes32 uid = bytes32(sig);
        return getEAS().getAttestation(uid).data;
    }

    /// @inheritdoc IClaimIssuer
    /// @dev `sig` must be a 32-byte EAS attestation UID (`abi.encodePacked(uid)`).
    ///      `data` must mirror the attestation field for field; see `_resolve`.
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, Structs.ClaimData calldata data)
        external
        view
        returns (bool)
    {
        return _resolve(_identity, claimTopic, sig, data) == ClaimStatus.Valid;
    }

    /// @inheritdoc IClaimIssuer
    function getClaimStatus(
        IIdentity _identity,
        uint256 claimTopic,
        bytes calldata sig,
        Structs.ClaimData calldata data
    ) external view returns (ClaimStatus status) {
        return _resolve(_identity, claimTopic, sig, data);
    }

    /// @inheritdoc IClaimIssuer
    /// @dev Always `false`: this issuer keeps no digest registry, so it has never
    ///      revoked a digest. Reverting here would abort compliance call chains
    ///      (`isVerified` -> `isDigestRevoked` -> `isClaimValid`) on perfectly valid
    ///      claims. Revocation lives on EAS and surfaces as `Revoked` through
    ///      `isClaimValid` / `getClaimStatus` — those are the source of truth.
    function isDigestRevoked(bytes32) external pure returns (bool) {
        return false;
    }

    /// @dev Live status resolution. Zero identity, missing config, missing attestation,
    ///      wrong schema, unaccepted attester, or `data` that does not mirror the attestation
    ///      map to `NotIssued`. Bad UID payload maps to `BadSignature`. EAS revocation and
    ///      expiry map to `Revoked` and `Expired`. Recipient binding to `_identity`
    ///      (self or any linked wallet, regardless of factory status) maps to `Valid`.
    ///      Wallet status is ignored on purpose; see the contract header.
    function _resolve(IIdentity _identity, uint256 topic, bytes calldata sig, Structs.ClaimData calldata data)
        internal
        view
        returns (ClaimStatus)
    {
        // The zero identity holds no claims. Without this, an unlinked recipient resolves to
        // zero on the wallet branch below and matches it.
        if (address(_identity) == address(0)) return ClaimStatus.NotIssued;

        bytes32 schema = getSchemaForTopic(topic);
        if (schema == bytes32(0)) return ClaimStatus.NotIssued;

        if (sig.length != 32) return ClaimStatus.BadSignature;
        bytes32 uid = bytes32(sig);
        if (uid == bytes32(0)) return ClaimStatus.BadSignature;

        Attestation memory attestation = getEAS().getAttestation(uid);
        if (
            attestation.uid == bytes32(0) || attestation.schema != schema
                || !getIsAttesterAllowed(topic, attestation.attester)
        ) {
            return ClaimStatus.NotIssued;
        }

        // The caller hands us a ClaimData that ERC-735 mirrors into storage verbatim. Nothing
        // upstream binds it to the attestation, so without this check a party allowed to add a
        // claim could pair a genuine UID with a fabricated payload and validity window and this
        // adapter would still call it Valid. Bind all three fields to what the attester signed.
        if (
            data.issuedAt != attestation.time || data.validUntil != attestation.expirationTime
                || keccak256(data.payload) != keccak256(attestation.data)
        ) {
            return ClaimStatus.NotIssued;
        }

        if (attestation.revocationTime != 0) return ClaimStatus.Revoked;
        if (attestation.expirationTime != 0 && block.timestamp >= attestation.expirationTime) {
            return ClaimStatus.Expired;
        }

        // Recipient is the identity itself. `isFactoryIdentity` blocks arbitrary contracts
        // from posing as `_identity`.
        if (attestation.recipient == address(_identity)) {
            return getFactory().isFactoryIdentity(address(_identity)) ? ClaimStatus.Valid : ClaimStatus.NotIssued;
        }

        // Recipient is a wallet linked to `_identity`. `getIdentityIncludingRevoked`
        // returns the identity for both Active and Revoked links; only `None` returns
        // zero. Status is ignored on purpose (see header, recovery deadlock argument).
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, attestation.recipient);
        (address linked,) = getFactory().getIdentityIncludingRevoked(envelope);
        if (linked == address(_identity)) return ClaimStatus.Valid;
        return ClaimStatus.NotIssued;
    }

    // Unsupported surface. Revocation lives on EAS, not on this contract.

    /// @inheritdoc IClaimIssuer
    function revokeClaimByDigest(bytes32) external pure {
        revert Errors.EASNotSupported();
    }

    /// @inheritdoc IClaimIssuer
    function addClaimTo(uint256, uint256, bytes calldata, Structs.ClaimData calldata, string calldata, IIdentity)
        external
        pure
    {
        revert Errors.EASNotSupported();
    }

    /// @inheritdoc IIdentity
    function getClaimHash(address, uint256, Structs.ClaimData memory) external pure returns (bytes32) {
        revert Errors.EASNotSupported();
    }

    /// @inheritdoc IIdentity
    function getIdentityType() external pure returns (uint256) {
        revert Errors.EASNotSupported();
    }

    // ERC-734 (key registry). The adapter is not an Identity so every method reverts.

    function addKey(bytes32, uint256, uint256) external pure returns (bool) {
        revert Errors.EASNotSupported();
    }

    function removeKey(bytes32, uint256) external pure returns (bool) {
        revert Errors.EASNotSupported();
    }

    function getKey(bytes32) external pure returns (uint256[] memory, uint256, bytes32) {
        revert Errors.EASNotSupported();
    }

    function getKeyPurposes(bytes32) external pure returns (uint256[] memory) {
        revert Errors.EASNotSupported();
    }

    function getKeysByPurpose(uint256) external pure returns (bytes32[] memory) {
        revert Errors.EASNotSupported();
    }

    function keyHasPurpose(bytes32, uint256) external pure returns (bool) {
        revert Errors.EASNotSupported();
    }

    // ERC-735 (claim registry). The adapter holds no claims so every method reverts.

    function addClaim(uint256, uint256, address, bytes calldata, Structs.ClaimData calldata, string calldata)
        external
        pure
        returns (bytes32)
    {
        revert Errors.EASNotSupported();
    }

    function removeClaim(bytes32) external pure returns (bool) {
        revert Errors.EASNotSupported();
    }

    function getClaim(bytes32)
        external
        pure
        returns (uint256, uint256, address, bytes memory, Structs.ClaimData memory, string memory)
    {
        revert Errors.EASNotSupported();
    }

    function getClaimIdsByTopic(uint256) external pure returns (bytes32[] memory) {
        revert Errors.EASNotSupported();
    }

}
