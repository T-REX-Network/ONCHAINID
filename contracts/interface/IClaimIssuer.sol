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
import { IIdentity } from "./IIdentity.sol";

interface IClaimIssuer is IIdentity {

    /**
     * @dev Reasons a claim can fail verification, in addition to `Valid`.
     */
    enum ClaimStatus {
        Valid,
        BadSignature,
        NotIssued,
        Revoked,
        NotYetValid,
        Expired
    }

    /**
     * @dev Emitted when a claim's digest is marked spent by the issuer (revoked).
     *      The same digest may also be marked spent by `removeClaim` on the
     *      holder side; that path emits `ClaimRemoved` (see IERC735) instead.
     */
    event ClaimRevoked(bytes32 indexed digest, address indexed issuer);

    /**
     * @dev Emitted when a claim is successfully added to an identity contract by this claim issuer.
     */
    event ClaimAddedTo(address indexed identity, uint256 topic, bytes signature, Structs.ClaimData data);

    /**
     * @dev Mark a claim digest as spent. Canonical revocation entry point.
     * @param digest the EIP-712 claim digest to mark spent.
     */
    function revokeClaimByDigest(bytes32 digest) external;

    /**
     * @dev Returns true if the digest has been marked spent (revoked or removed).
     * @param digest the EIP-712 claim digest to check.
     */
    function isDigestRevoked(bytes32 digest) external view returns (bool);

    /**
     * @dev Add a claim to a target identity contract. Validates that the signature is
     *      from a CLAIM_SIGNER on this issuer, that the digest is not spent, and that
     *      the time bounds in `_data` are honored before forwarding to the target.
     */
    function addClaimTo(
        uint256 _topic,
        uint256 _scheme,
        bytes calldata _signature,
        Structs.ClaimData calldata _data,
        string calldata _uri,
        IIdentity _identity
    ) external;

    /**
     * @dev Checks if a claim is valid.
     * @param _identity the identity contract related to the claim
     * @param claimTopic the claim topic of the claim
     * @param sig the signature of the claim
     * @param data the structured claim data
     * @return claimValid true if the claim is valid, false otherwise
     */
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, Structs.ClaimData calldata data)
        external
        view
        returns (bool);

    /**
     * @dev Detailed status for a claim. Distinguishes "spent" from "expired" from
     *      "bad signature", which off-chain consumers need to surface to users.
     * @return status the detailed status (see ClaimStatus).
     */
    function getClaimStatus(
        IIdentity _identity,
        uint256 claimTopic,
        bytes calldata sig,
        Structs.ClaimData calldata data
    ) external view returns (ClaimStatus status);

}
