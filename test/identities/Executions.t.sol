// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";

/// @notice Coverage for the queue-style execution surface exposed by KeyApprovalModule
///         through the identity's ERC-7579 fallback handler.
contract ExecutionsTest is OnchainIDSetup {

    /// @notice The execution nonce lives on the queue module and is reachable through the
    ///         identity via `IKeyExecutor.getCurrentNonce` (resolved by the fallback handler).
    function test_nonceLivesOnModule() public view {
        uint256 nonce = IKeyExecutor(address(aliceIdentity)).getCurrentNonce();
        // No executions have been queued via this path in the base fixture.
        assertEq(nonce, 0);
    }

}
