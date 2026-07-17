// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title  IEAS (minimal)
 * @notice Vendored subset of the Ethereum Attestation Service interface. Only the surface the
 *         ONCHAINID EAS adapter reads is included: one struct and one view function.
 *
 * @dev    Full interface: https://github.com/ethereum-attestation-service/eas-contracts. The
 *         eas-contracts package is not pulled in as a dependency because the adapter is a
 *         stateless view over EAS and only consumes what is declared here. Field ordering and
 *         types must match the upstream `Attestation` layout so `getAttestation` decodes
 *         correctly.
 */
struct Attestation {
    bytes32 uid;
    bytes32 schema;
    uint64 time;
    uint64 expirationTime;
    uint64 revocationTime;
    bytes32 refUID;
    address recipient;
    address attester;
    bool revocable;
    bytes data;
}

interface IEAS {

    /**
     * @notice Read a single attestation by UID.
     * @dev    A missing attestation is returned with `uid == 0`.
     */
    function getAttestation(bytes32 uid) external view returns (Attestation memory);

}
