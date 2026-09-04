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

/// @title IReputationRegistry
/// @notice A single per-identity reputation primitive that any feature can read.
///
///         The registry is a thin key-value store. Two write seams, both gated
///         by the AccessManager's REPUTATION_MANAGER role:
///
///         * {setReputation} writes a per-identity explicit score.
///         * {setDefault} writes a per-type default score.
///
///         One canonical read seam, {reputationOf}:
///         * If an explicit entry exists (`setAt != 0`), its score is returned,
///           including an explicit `0` (which is how a manager revokes trust
///           without deleting the entry).
///         * Otherwise the lookup falls back to `defaultFor[type]` where `type`
///           is read from the identity itself via `IIdentity.getIdentityType()`.
///
///         Factory-membership gating. The fallback path is gated on
///         {IIdentityFactory.isFactoryIdentity}: an arbitrary contract that
///         self-declares type 5 cannot inherit the CLAIM_ISSUER default. The
///         explicit-entry path bypasses the factory check because the manager
///         may want to score externally-deployed identities by hand.
interface IReputationRegistry {

    /// @dev Per-identity entry. Packs into a single 32-byte slot. `setAt == 0`
    ///      means "no explicit entry" and the lookup falls back to a per-type
    ///      default. `score` is `uint128` because no reputation use case
    ///      anticipates needing more than 2^128 - 1 distinct levels, and packing
    ///      keeps the per-identity slot count at one.
    struct Entry {
        uint128 score;
        uint128 setAt;
    }

    /// @notice Emitted whenever an identity's explicit reputation entry is written.
    ///         Both the previous score and the writer are recorded so off-chain
    ///         indexers can reconstruct full history from this event alone.
    /// @param identity The identity whose entry changed.
    /// @param oldScore Previous explicit score (`0` if the entry was uninitialized).
    /// @param newScore New explicit score.
    /// @param setter   `msg.sender` on the call that produced the change.
    event ReputationSet(address indexed identity, uint128 oldScore, uint128 newScore, address indexed setter);

    /// @notice Emitted whenever the default score for a given identity type changes.
    /// @param identityType The identity type whose default changed.
    /// @param oldDefault   Previous default score for that type.
    /// @param newDefault   New default score for that type.
    event DefaultSet(uint256 indexed identityType, uint128 oldDefault, uint128 newDefault);

    /// @notice Emitted whenever the global claim-add auto-approval threshold changes.
    ///         Consumers compare this against {reputationOf} to decide whether a
    ///         claim-add should auto-approve.
    /// @param oldThreshold Previous threshold.
    /// @param newThreshold New threshold.
    event ClaimAddThresholdSet(uint128 oldThreshold, uint128 newThreshold);

    // ---- Reads (open) ----

    /// @notice Effective reputation score for `identity`.
    ///         Returns the explicit entry when {setReputation} has been called
    ///         for `identity` (including an explicit `0`), otherwise the per-type
    ///         default, but only when `identity` is a factory-deployed identity.
    ///         Non-factory identities without an explicit entry read `0`.
    function reputationOf(address identity) external view returns (uint128);

    /// @notice Raw explicit entry for `identity`. Does **not** fall back to the
    ///         per-type default. `setAt == 0` means "no explicit entry."
    ///         Useful for callers that want to distinguish "manager revoked to 0"
    ///         from "never written."
    function entryOf(address identity) external view returns (uint128 score, uint128 setAt);

    /// @notice Default score for `identityType`. Written via {setDefault}.
    function defaultFor(uint256 identityType) external view returns (uint128);

    /// @notice Global threshold consumers compare against {reputationOf} when
    ///         deciding whether a claim-add should auto-approve. Tunable by the
    ///         REPUTATION_MANAGER via {setClaimAddThreshold}.
    function claimAddThreshold() external view returns (uint128);

    // ---- Writes: REPUTATION_MANAGER (restricted via AccessManager) ----

    /// @notice Set the explicit reputation score for `identity`. Use `0` to
    ///         revoke trust without removing the entry. `restricted` via the AM.
    function setReputation(address identity, uint128 newScore) external;

    /// @notice Set the default reputation score for `identityType`. `restricted`
    ///         via the AM.
    function setDefault(uint256 identityType, uint128 newDefault) external;

    /// @notice Set the global claim-add auto-approval threshold consumers use.
    ///         `restricted` via the AM.
    function setClaimAddThreshold(uint128 newThreshold) external;

}
