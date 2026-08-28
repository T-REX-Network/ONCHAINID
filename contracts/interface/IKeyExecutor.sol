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

pragma solidity ^0.8.28;

/**
 * @title IKeyExecutor
 * @notice Externalized execution surface for ERC-734 identities, served by the
 *         {KeyApprovalModule} via the identity's ERC-7579 fallback handler.
 *
 * @dev Exposes the legacy `execute` / `approve` ABI as a separate Solidity type so that
 *      callers can `IKeyExecutor(address(identity)).execute(...)` without forcing the
 *      account contract itself to declare these as concrete methods. At the wire level
 *      these selectors are identical to the original ERC-734 selectors, so on-chain
 *      consumers keep calling them as ERC-734 calls.
 *
 *      The lifecycle events below are NOT the canonical ERC-734 ones: the queue module is a
 *      singleton emitting on its own address for every identity that installs it, so each
 *      event carries `address indexed account` (the identity) as its first field. Indexers
 *      must filter on that field, not on the emitter.
 *
 *      See {KeyApprovalModule} for the implementation and the auto-approval rule table.
 */
interface IKeyExecutor {

    /// @dev Emitted when an identity queues an execution via {execute}.
    event ExecutionRequested(
        address indexed account,
        uint256 indexed executionId,
        address indexed to,
        uint256 value,
        bytes data,
        address proposer
    );

    /// @dev Emitted when an execution is approved (or rejected) via {approve}.
    event Approved(address indexed account, uint256 indexed executionId, bool approved);

    /// @dev Emitted when an uninstall voids every request queued below `firstValidId`.
    event QueueInvalidated(address indexed account, uint256 firstValidId);

    /// @dev Emitted when an approved execution successfully dispatches through the account.
    event Executed(address indexed account, uint256 indexed executionId, address indexed to, uint256 value, bytes data);

    /// @dev Emitted when an approved execution reverts inside the account.
    event ExecutionFailed(
        address indexed account, uint256 indexed executionId, address indexed to, uint256 value, bytes data
    );

    /**
     * @notice Queue (and possibly auto-execute) a call from the identity.
     * @return executionId opaque id used with {approve} if the call was queued, not auto-approved.
     */
    function execute(address _to, uint256 _value, bytes calldata _data) external payable returns (uint256 executionId);

    /**
     * @notice Approve (or reject) a previously queued execution. Caller's keyHash is recovered
     *         from the ERC-2771 trailing-bytes convention.
     */
    function approve(uint256 _id, bool _shouldApprove) external returns (bool success);

    /// @notice Current execution nonce for the calling identity.
    function getCurrentNonce() external view returns (uint256);

}
