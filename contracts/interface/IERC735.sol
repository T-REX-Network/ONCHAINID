// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Structs } from "../storage/Structs.sol";

/**
 * @dev interface of the ERC735 (Claim Holder) standard as defined in the EIP.
 *
 * Note on ABI: this interface follows the EIP-735 shape, with two OnchainID-specific
 * adjustments. The claim's signed payload (`data`) is structured as `Structs.ClaimData`
 * (`issuedAt`, `validUntil`, `payload`) instead of raw bytes, which makes typed-data
 * signing legible to wallets and lets claims carry time bounds without convention. And
 * the events carry the subject identity as their first indexed field: the claim registry
 * is served by a module singleton shared across identities, so neither the emitter
 * address nor `claimId` (derived from `(issuer, topic)` alone) can attribute a log to an
 * identity. `claimId` is unindexed to make room — it stays filterable through the
 * indexed `topic` and `issuer` it is derived from.
 */
interface IERC735 {

    /**
     * @dev Emitted when a claim was added.
     *
     * Specification: MUST be triggered when a claim was successfully added.
     */
    event ClaimAdded(
        address indexed identity,
        bytes32 claimId,
        uint256 indexed topic,
        uint256 scheme,
        address indexed issuer,
        bytes signature,
        Structs.ClaimData data,
        string uri
    );

    /**
     * @dev Emitted when a claim was removed.
     *
     * Specification: MUST be triggered when removeClaim was successfully called.
     */
    event ClaimRemoved(
        address indexed identity,
        bytes32 claimId,
        uint256 indexed topic,
        uint256 scheme,
        address indexed issuer,
        bytes signature,
        Structs.ClaimData data,
        string uri
    );

    /**
     * @dev Emitted when a claim was changed.
     *
     * Specification: MUST be triggered when addClaim was successfully called on an existing claimId.
     */
    event ClaimChanged(
        address indexed identity,
        bytes32 claimId,
        uint256 indexed topic,
        uint256 scheme,
        address indexed issuer,
        bytes signature,
        Structs.ClaimData data,
        string uri
    );

    /**
     * @dev Add or update a claim.
     *
     * Triggers Event: `ClaimAdded`, `ClaimChanged`
     *
     * Specification: Add or update a claim from an issuer.
     *
     * _signature is over an EIP-712 typed data hash computed by the issuer contract's `getClaimHash()`.
     * The EIP-712 type is:
     *   `Claim(uint256 topic,address subject,ClaimData data)`
     *   `ClaimData(uint256 issuedAt,uint256 validUntil,bytes payload)`
     * Claim IDs are generated using `keccak256(abi.encode(address issuer_address, uint256 topic))`.
     */
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address issuer,
        bytes calldata _signature,
        Structs.ClaimData calldata _data,
        string calldata _uri
    ) external returns (bytes32 claimRequestId);

    /**
     * @dev Removes a claim.
     *
     * Triggers Event: `ClaimRemoved`
     *
     * Claim IDs are generated using `keccak256(abi.encode(address issuer_address, uint256 topic))`.
     * The removed claim's EIP-712 digest is marked spent, so the exact same `(issuer, topic, data)`
     * cannot be re-added.
     */
    function removeClaim(bytes32 _claimId) external returns (bool success);

    /**
     * @dev Get a claim by its ID.
     *
     * Claim IDs are generated using `keccak256(abi.encode(address issuer_address, uint256 topic))`.
     */
    function getClaim(bytes32 _claimId)
        external
        view
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            Structs.ClaimData memory data,
            string memory uri
        );

    /**
     * @dev Returns an array of claim IDs by topic.
     */
    function getClaimIdsByTopic(uint256 _topic) external view returns (bytes32[] memory claimIds);

}
