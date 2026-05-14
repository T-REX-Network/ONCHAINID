// SPDX-License-Identifier: GPL-3.0
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
 *      consumers and indexers continue to interpret them as ERC-734 calls.
 *
 *      See {KeyApprovalModule} for the implementation and the auto-approval rule table.
 */
interface IKeyExecutor {

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
