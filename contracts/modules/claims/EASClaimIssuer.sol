// SPDX-License-Identifier: GPL-3.0
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
 *         attester allowlist. Both EAS and factory addresses are immutable so the
 *         admin cannot silently repoint them.
 *
 *         An attestation may name the identity itself (identities are ERC-7579 smart
 *         accounts) or a wallet linked to the identity in `IdentityFactory`. The
 *         wallet's factory status is intentionally ignored: the attestation belongs
 *         to the identity, and requiring `Active` would deadlock recovery on a
 *         compromised wallet. Kills happen elsewhere: attester revokes on EAS, holder
 *         removes the local record via `removeClaim`.
 *
 *         The `IClaimIssuer` `signature` field carries the EAS attestation UID as a
 *         bare 32-byte word (`abi.encodePacked(uid)`). Length-32 check rejects any
 *         other shape.
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
    ///      the attestation's own `schema` field to equal the mapped value (this second
    ///      check prevents cross-topic contamination). Read via {getSchemaForTopic}.
    mapping(uint256 topic => bytes32 schema) private _schemaOf;

    /// @dev Attesters whose EAS attestations this adapter accepts. Any `address` can
    ///      write an attestation on EAS; only those in this set are treated as trusted
    ///      issuers here. Managed like `trustedIssuersRegistry` on the OnchainID side.
    ///      Read via {getIsAttesterAllowed}.
    mapping(address attester => bool allowed) private _isAttesterAllowed;

    /// @dev Adapter initialized. Emits the immutable EAS and factory addresses so
    ///      indexers can catalog every deployed adapter with a single topic scan.
    event AdapterInitialized(address indexed eas, address indexed factory);

    /// @dev Schema binding changed. `schema == 0` means the topic was unbound.
    event SchemaForTopicSet(uint256 indexed topic, bytes32 indexed schema);

    /// @dev Attester allowlist changed. Monitor `allowed == true` events: they widen
    ///      the trust surface.
    event AttesterSet(address indexed attester, bool allowed);

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

    /// @notice Add or remove an attester from the accepted set. Adding widens the trust
    ///         surface: attestations from `attester` under a configured schema will pass.
    function setAttester(address attester, bool allowed) external restricted {
        _isAttesterAllowed[attester] = allowed;
        emit AttesterSet(attester, allowed);
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

    /// @notice Whether `attester` is in the accepted set.
    function getIsAttesterAllowed(address attester) public view returns (bool) {
        return _isAttesterAllowed[attester];
    }

    /// @notice Raw `data` field of the attestation carried by `sig`. Useful when the
    ///         schema encodes attribute values the caller wants to decode.
    /// @dev    Returns empty bytes if `sig` is not a 32-byte UID or the attestation does
    ///         not exist. Does not check schema, attester, revocation, or expiry. Pair
    ///         with `getClaimStatus` when validity matters.
    function getAttestationData(bytes calldata sig) external view returns (bytes memory) {
        if (sig.length != 32) return "";
        bytes32 uid = bytes32(sig);
        return getEAS().getAttestation(uid).data;
    }

    /// @inheritdoc IClaimIssuer
    /// @dev `sig` must be a 32-byte EAS attestation UID (`abi.encodePacked(uid)`).
    ///      `data` is ignored: EAS carries its own time bounds.
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

    /// @dev Live status resolution. Missing config, missing attestation, wrong schema,
    ///      or unaccepted attester map to `NotIssued`. Bad UID payload maps to
    ///      `BadSignature`. EAS revocation and expiry map to `Revoked` and `Expired`.
    ///      Recipient binding to `_identity` (self or any linked wallet, regardless of
    ///      factory status) maps to `Valid`. Wallet status is ignored on purpose; see
    ///      the contract header.
    function _resolve(
        IIdentity _identity,
        uint256 topic,
        bytes calldata sig,
        Structs.ClaimData calldata /*data*/
    )
        internal
        view
        returns (ClaimStatus)
    {
        bytes32 schema = getSchemaForTopic(topic);
        if (schema == bytes32(0)) return ClaimStatus.NotIssued;

        if (sig.length != 32) return ClaimStatus.BadSignature;
        bytes32 uid = bytes32(sig);
        if (uid == bytes32(0)) return ClaimStatus.BadSignature;

        Attestation memory attestation = getEAS().getAttestation(uid);
        if (
            attestation.uid == bytes32(0) || attestation.schema != schema || !getIsAttesterAllowed(attestation.attester)
        ) {
            return ClaimStatus.NotIssued;
        }

        if (attestation.revocationTime != 0) return ClaimStatus.Revoked;
        if (attestation.expirationTime != 0 && block.timestamp > attestation.expirationTime) {
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
    function isDigestRevoked(bytes32) external pure returns (bool) {
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
