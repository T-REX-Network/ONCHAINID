// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Attestation, IEAS } from "contracts/vendor/eas/IEAS.sol";

/**
 * @title  MockEAS
 * @notice Minimal EAS stand-in for tests. Attestations are written by UID and read back
 *         through `getAttestation`. Absent UIDs return the zero attestation, matching
 *         upstream EAS behavior.
 */
contract MockEAS is IEAS {

    mapping(bytes32 uid => Attestation) private _attestations;

    /// @notice Store an attestation under `attestation.uid`. Any prior entry with the same
    ///         uid is overwritten so tests can walk the adapter's rejection paths in place.
    function setAttestation(Attestation calldata attestation) external {
        _attestations[attestation.uid] = attestation;
    }

    /// @notice Revoke an existing attestation by setting `revocationTime`.
    function revoke(bytes32 uid, uint64 revocationTime) external {
        _attestations[uid].revocationTime = revocationTime;
    }

    /// @notice Delete an attestation, mimicking a UID that was never issued.
    function clear(bytes32 uid) external {
        delete _attestations[uid];
    }

    /// @inheritdoc IEAS
    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        return _attestations[uid];
    }

}
