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
 * @notice Stateless ClaimIssuer adapter that resolves ERC-3643 claims against EAS attestations
 *         live on every call. The adapter holds no claim state; EAS is the source of truth and
 *         `isClaimValid` re-reads it each time.
 *
 * @dev    Two recipient layouts are supported. The attestation may name the identity contract
 *         itself as recipient (the identity is an ERC-7579 smart account so it can receive
 *         attestations directly), or it may name an EVM wallet that is Active-linked to the
 *         identity in the IdentityFactory global registry. A wallet whose factory status is
 *         Revoked fails validation: the on-chain link stays visible but no longer authenticates.
 *
 *         The following surfaces cause `isClaimValid` to return false: EAS attestation revoked
 *         (`revocationTime != 0`), EAS attestation expired, attester not in the accepted set,
 *         schema does not match the topic, recipient wallet revoked or not linked, and topic
 *         with no configured schema.
 *
 *         The IClaimIssuer `signature` bytes carry the EAS attestation UID (a bare 32-byte
 *         word). This keeps the interface compatible with ClaimsModule without changing it.
 *         Use `encodeSignature` so the packing is consistent across integrators.
 *
 *         Not supported in v1: off-chain EAS attestations, non-EVM linked wallets, and
 *         cross-chain EAS reads. Every method that would mutate identity or claim state
 *         reverts with `Errors.NotSupported` because the adapter is not itself an Identity.
 */
contract EASClaimIssuer is IClaimIssuer, AccessManaged {

    /// @dev EAS deployment this adapter reads from. Same-chain only. Settable behind
    ///      `restricted` so operators can point the adapter at a different EAS deployment
    ///      (chain migration, upgraded EAS instance) without redeploying.
    IEAS public eas;

    /// @dev Global identity registry consulted to resolve linked wallets.
    IIdentityFactory public immutable FACTORY;

    /// @dev Topic to EAS schema UID mapping. Unset topics reject.
    mapping(uint256 topic => bytes32 schema) public schemaOf;

    /// @dev Accepted attester allowlist. An attestation from an address outside this set is
    ///      rejected regardless of schema and revocation state.
    mapping(address attester => bool allowed) public isAttesterAllowed;

    /// @dev Emitted when the schema binding for a topic changes.
    event SchemaForTopicSet(uint256 indexed topic, bytes32 indexed schema);

    /// @dev Emitted when the accepted attester allowlist changes.
    event AttesterSet(address indexed attester, bool allowed);

    /// @dev Emitted when the EAS instance the adapter reads from is repointed.
    event EASSet(address indexed eas);

    /**
     * @param authority_ AccessManager instance backing `restricted` setters.
     * @param eas_ The EAS core contract on this chain.
     * @param factory_ The IdentityFactory (global registry).
     */
    constructor(address authority_, IEAS eas_, IIdentityFactory factory_) AccessManaged(authority_) {
        require(address(eas_) != address(0), Errors.ZeroAddress());
        require(address(factory_) != address(0), Errors.ZeroAddress());
        eas = eas_;
        FACTORY = factory_;
        emit EASSet(address(eas_));
    }

    /**
     * @notice Point the adapter at a different EAS deployment. Zero rejects.
     */
    function setEAS(IEAS newEAS) external restricted {
        require(address(newEAS) != address(0), Errors.ZeroAddress());
        eas = newEAS;
        emit EASSet(address(newEAS));
    }

    /**
     * @notice Bind an ERC-3643 claim topic to an EAS schema UID. Pass `schema = 0` to unbind
     *         and disable the topic on this adapter.
     */
    function setSchemaForTopic(uint256 topic, bytes32 schema) external restricted {
        schemaOf[topic] = schema;
        emit SchemaForTopicSet(topic, schema);
    }

    /**
     * @notice Add or remove an attester from the accepted set.
     */
    function setAttester(address attester, bool allowed) external restricted {
        require(attester != address(0), Errors.ZeroAddress());
        isAttesterAllowed[attester] = allowed;
        emit AttesterSet(attester, allowed);
    }

    /**
     * @notice Encode an EAS attestation UID into the `signature` bytes expected by
     *         `isClaimValid`, `getClaimStatus`, and `IERC735.addClaim` when the issuer is this
     *         adapter. Integrators should call this helper so the packing is not a source of
     *         drift.
     *
     * @dev    Returns the UID as a bare 32-byte word, which matches the adapter's
     *         `sig.length == 32` check.
     */
    function encodeSignature(bytes32 uid) external pure returns (bytes memory) {
        return abi.encodePacked(uid);
    }

    /**
     * @inheritdoc IClaimIssuer
     * @dev  `sig` must be a 32-byte EAS attestation UID (see `encodeSignature`). `data` is
     *       ignored: EAS carries its own `time` and `expirationTime`, which are the
     *       authoritative time bounds.
     */
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

    /**
     * @dev Live status resolution. Order of checks mirrors `IClaimIssuer.ClaimStatus` so
     *      off-chain consumers can surface EAS failures with existing UI. Missing schema,
     *      missing attestation, wrong schema, or unaccepted attester map to `NotIssued`.
     *      Malformed UID payload maps to `BadSignature`. EAS revocation and expiry map to
     *      `Revoked` and `Expired`. Recipient binding to `_identity` (self or Active-linked
     *      wallet) maps to `Valid`.
     */
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
        bytes32 schema = schemaOf[topic];
        if (schema == bytes32(0)) return ClaimStatus.NotIssued;

        if (sig.length != 32) return ClaimStatus.BadSignature;
        bytes32 uid = bytes32(sig[:32]);
        if (uid == bytes32(0)) return ClaimStatus.BadSignature;

        Attestation memory attestation = eas.getAttestation(uid);
        if (attestation.uid == bytes32(0)) return ClaimStatus.NotIssued;
        if (attestation.schema != schema) return ClaimStatus.NotIssued;
        if (!isAttesterAllowed[attestation.attester]) return ClaimStatus.NotIssued;

        if (attestation.revocationTime != 0) return ClaimStatus.Revoked;
        if (attestation.expirationTime != 0 && block.timestamp > attestation.expirationTime) {
            return ClaimStatus.Expired;
        }

        // Recipient is the identity itself. `isFactoryIdentity` blocks arbitrary contracts
        // from passing themselves as `_identity`. The linked-wallet branch below does not
        // need this check; the factory only knows about identities it deployed.
        if (attestation.recipient == address(_identity)) {
            return FACTORY.isFactoryIdentity(address(_identity)) ? ClaimStatus.Valid : ClaimStatus.NotIssued;
        }

        // Recipient is an EVM wallet that must be Active-linked to `_identity`.
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, attestation.recipient);
        (address linked, IIdentityFactory.AccountStatus status) = FACTORY.getIdentityIncludingRevoked(envelope);
        if (linked == address(_identity) && status == IIdentityFactory.AccountStatus.Active) {
            return ClaimStatus.Valid;
        }
        return ClaimStatus.NotIssued;
    }

    // Unsupported IClaimIssuer surface. Revocation is driven by EAS, not by a spent-digest set
    // on this contract.

    /// @inheritdoc IClaimIssuer
    function revokeClaimByDigest(bytes32) external pure {
        revert Errors.NotSupported();
    }

    /// @inheritdoc IClaimIssuer
    function isDigestRevoked(bytes32) external pure returns (bool) {
        revert Errors.NotSupported();
    }

    /// @inheritdoc IClaimIssuer
    function addClaimTo(uint256, uint256, bytes calldata, Structs.ClaimData calldata, string calldata, IIdentity)
        external
        pure
    {
        revert Errors.NotSupported();
    }

    /// @inheritdoc IIdentity
    function getClaimHash(address, uint256, Structs.ClaimData memory) external pure returns (bytes32) {
        revert Errors.NotSupported();
    }

    /// @inheritdoc IIdentity
    function getIdentityType() external pure returns (uint256) {
        revert Errors.NotSupported();
    }

    // ERC-734 (key registry). The adapter is not an Identity so every method reverts.

    function addKey(bytes32, uint256, uint256) external pure returns (bool) {
        revert Errors.NotSupported();
    }

    function removeKey(bytes32, uint256) external pure returns (bool) {
        revert Errors.NotSupported();
    }

    function getKey(bytes32) external pure returns (uint256[] memory, uint256, bytes32) {
        revert Errors.NotSupported();
    }

    function getKeyPurposes(bytes32) external pure returns (uint256[] memory) {
        revert Errors.NotSupported();
    }

    function getKeysByPurpose(uint256) external pure returns (bytes32[] memory) {
        revert Errors.NotSupported();
    }

    function keyHasPurpose(bytes32, uint256) external pure returns (bool) {
        revert Errors.NotSupported();
    }

    // ERC-735 (claim registry). The adapter holds no claims so every method reverts.

    function addClaim(uint256, uint256, address, bytes calldata, Structs.ClaimData calldata, string calldata)
        external
        pure
        returns (bytes32)
    {
        revert Errors.NotSupported();
    }

    function removeClaim(bytes32) external pure returns (bool) {
        revert Errors.NotSupported();
    }

    function getClaim(bytes32)
        external
        pure
        returns (uint256, uint256, address, bytes memory, Structs.ClaimData memory, string memory)
    {
        revert Errors.NotSupported();
    }

    function getClaimIdsByTopic(uint256) external pure returns (bytes32[] memory) {
        revert Errors.NotSupported();
    }

}
