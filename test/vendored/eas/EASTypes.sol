// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Attestation, IEAS } from "contracts/vendor/eas/IEAS.sol";

/// @notice Fields EAS accepts on `attest`. Struct layout matches the mainnet EAS ABI.
struct AttestationRequestData {
    address recipient;
    uint64 expirationTime;
    bool revocable;
    bytes32 refUID;
    bytes data;
    uint256 value;
}

/// @notice `attest` outer envelope: schema + data.
struct AttestationRequest {
    bytes32 schema;
    AttestationRequestData data;
}

/// @notice Fields EAS accepts on `revoke`.
struct RevocationRequestData {
    bytes32 uid;
    uint256 value;
}

struct RevocationRequest {
    bytes32 schema;
    RevocationRequestData data;
}

/// @notice Test-only extension of `IEAS` with the write methods tests need to drive real
///         EAS bytecode. Production `IEAS` under `contracts/vendor/eas/` intentionally
///         exposes only `getAttestation` since the adapter is a stateless reader.
interface IEASTest is IEAS {

    function attest(AttestationRequest calldata request) external payable returns (bytes32);
    function revoke(RevocationRequest calldata request) external payable;

}

/// @notice Minimal `SchemaRegistry` surface the tests use to register schemas before
///         calling `attest`. `resolver` and `revocable` are the standard EAS parameters.
interface ISchemaRegistryTest {

    function register(string calldata schema, address resolver, bool revocable) external returns (bytes32);
    function getSchema(bytes32 uid) external view returns (SchemaRecord memory);

}

/// @notice Minimal `SchemaRecord` mirroring what mainnet SchemaRegistry stores. Used to
///         verify a schema was registered.
struct SchemaRecord {
    bytes32 uid;
    address resolver;
    bool revocable;
    string schema;
}
