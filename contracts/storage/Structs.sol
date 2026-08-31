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

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

library Structs {

    /**
     *  @dev Definition of the structure of a Key.
     *
     *  Specification: Keys are cryptographic public keys, or contract addresses associated with this identity.
     *  The structure should be as follows:
     *  key: A public key owned by this identity
     *  purposes: uint256[] Array of the key purposes, like KeyPurposes.MANAGEMENT = MANAGEMENT,
     *  KeyPurposes.ACTION = ACTION
     *  keyType: The type of key used, which would be a uint256 for different key types. e.g. KeyTypes.ECDSA = ECDSA,
     *  KeyTypes.RSA = RSA, etc.
     *  key: bytes32 The public key. // Its the Keccak256 hash of the key
     */
    struct Key {
        EnumerableSet.UintSet purposes;
        uint256 keyType;
        bytes32 key;
        /// @dev ERC-7913 signer bytes used for on-chain signature verification.
        ///      Capped at {MAX_SIGNER_DATA_LENGTH} (fits a 20-byte verifier + RSA-4096 key).
        bytes signerData;
        /// @dev Non-cryptographic metadata for dapps (e.g. WebAuthn credentialId). Empty for ECDSA keys.
        ///      Capped at {MAX_CLIENT_DATA_LENGTH} (WebAuthn credentialIds are spec-capped at 1023 bytes).
        bytes clientData;
    }

    /// @dev Caps on the dynamic fields of {Key}, enforced when a key is registered.
    uint256 internal constant MAX_SIGNER_DATA_LENGTH = 1024;
    uint256 internal constant MAX_CLIENT_DATA_LENGTH = 1024;

    /**
     *  @dev Definition of the structure of an Execution
     *
     *  Specification: Executions are requests for transactions to be issued by the ONCHAINID
     *  to: address of contract to interact with, can be address(this)
     *  value: ETH to transfer with the transaction
     *  data: payload of the transaction to execute
     *  approved: approval status of the Execution
     *  executed: execution status of the Execution (set as false when the Execution is created
     *  and updated to true when the Execution is processed)
     */
    struct Execution {
        address to;
        uint256 value;
        bytes data;
        bool approved;
        bool executed;
    }

    /**
     *  @dev Definition of the structure of a Claim.
     *
     *  Specification: Claims are information an issuer has about the identity holder.
     *  The structure should be as follows:
     *  claim: A claim published for the Identity.
     *  topic: A uint256 number which represents the topic of the claim. (e.g. biometric,
     *  residence (ToBeDefined: number schemes, sub topics based on number ranges??))
     *  scheme : The scheme with which this claim SHOULD be verified or how it should be processed. Its a uint256 for
     *  different schemes. E.g. could mean contract verification, where the data will be call data, and the issuer a
     *  contract address to call (ToBeDefined). Those can also mean different key types e.g. KeyTypes.ECDSA = ECDSA,
     *  KeyTypes.RSA = RSA, etc.
     *  (ToBeDefined)
     *  issuer: The issuers identity contract address, or the address used to sign the above signature. If an
     *  identity contract, it should hold the key with which the above message was signed, if the key is not present
     *  anymore, the claim SHOULD be treated as invalid. The issuer can also be a contract address itself, at which the
     *  claim can be verified using the call data.
     *  signature: Signature which is the proof that the claim issuer issued a claim of topic for this identity. it
     *  MUST be a signed message of the following structure:
     *  `keccak256(abi.encode(identityHolder_address, topic, data))`
     *  data: The hash of the claim data, sitting in another location, a bit-mask, call data, or actual data based on
     *  the claim scheme.
     *  uri: The location of the claim, this can be HTTP links, swarm hashes, IPFS hashes, and such.
     */
    struct Claim {
        uint256 topic;
        uint256 scheme;
        address issuer;
        bytes signature;
        ClaimData data;
        string uri;
    }

    /**
     *  @dev Typed envelope for the signed portion of a Claim.
     *
     *  issuedAt:     block timestamp when the issuer signed the claim. MUST be > 0.
     *                `block.timestamp < issuedAt` means the claim is not yet valid.
     *  validUntil:   block timestamp after which the claim expires. 0 means no expiry.
     *  metadataHash: the EIP-712 hash of `Metadata(uint256 scheme,string uri)`. Binds the
     *                claim's scheme and uri to the signature; every add checks it against the
     *                submitted values.
     *  payload:      topic-specific claim contents.
     *
     *  The EIP-712 type is nested as
     *  `ClaimData(uint256 issuedAt,uint256 validUntil,Metadata metadata,bytes payload)` with
     *  `Metadata(uint256 scheme,string uri)`, so wallets render each field legibly during
     *  typed-data signing — including the actual scheme and uri — instead of surfacing an
     *  opaque hex blob.
     */
    struct ClaimData {
        uint256 issuedAt;
        uint256 validUntil;
        bytes32 metadataHash;
        bytes payload;
    }

    /// @dev Caps on the dynamic fields of {Claim} and {ClaimData}, enforced when a claim is
    ///      added. They keep every claim small enough to remove in one block.
    uint256 internal constant MAX_CLAIM_SIGNATURE_LENGTH = 2048;
    uint256 internal constant MAX_CLAIM_PAYLOAD_LENGTH = 2048;
    uint256 internal constant MAX_CLAIM_URI_LENGTH = 2048;

    /**
     *  @dev Definition of the structure of a KeyParam, used by the factory to set up keys on a new identity.
     *
     *  keyHash: keccak256(signerData) for the key
     *  purpose: Key purpose (MANAGEMENT=1, ACTION=2, CLAIM_SIGNER=3, ENCRYPTION=4, CLAIM_ADDER=5)
     *  keyType: Key type (ECDSA=1, RSA=2, WEBAUTHN=3)
     *  signerData: ERC-7913 signer bytes (abi.encodePacked(address) for ECDSA, etc.)
     *  clientData: Non-cryptographic metadata (e.g. WebAuthn credentialId) — not used for on-chain verification
     */
    struct KeyParam {
        bytes32 keyHash;
        uint256 purpose;
        uint256 keyType;
        bytes signerData;
        bytes clientData;
    }

    /**
     *  @dev Definition of an ERC-7579 module to install on an identity during factory deployment.
     *  The frontend decides which modules (validators, executors, fallback handlers) and their init data.
     *
     *  moduleType: ERC-7579 module type (1=VALIDATOR, 2=EXECUTOR, 3=FALLBACK, 4=HOOK)
     *  module: Address of the module singleton
     *  initData: Module-specific initialization data (e.g. signer address for ECDSA, keyHash+qx+qy for WebAuthn)
     *  purpose: If non zero, the factory registers `hashAddress(module)` in the
     *           key registry with this purpose. Executor modules need this to dispatch through
     *           `executeFromExecutor`, and so do fallback handlers that call privileged
     *           self targeted functions. On uninstall the purpose is removed automatically,
     *           so you don't need to follow up with `removeKey`.
     */
    struct ModuleInstall {
        uint256 moduleType;
        address module;
        bytes initData;
        uint256 purpose;
    }

}
