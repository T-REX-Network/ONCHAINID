// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";

/// @notice Tests for the legacy ERC-734 execute/approve queue served by KeyApprovalModule.
///         The identity holds the ETH; the module never keeps any after a call returns.
contract ExecutionsTest is OnchainIDSetup {

    /// @notice The execution nonce is stored on the module and reachable through the identity.
    function test_nonceLivesOnModule() public view {
        uint256 nonce = IKeyExecutor(address(aliceIdentity)).getCurrentNonce();
        // No executions have been queued via this path in the base fixture.
        assertEq(nonce, 0);
    }

    // -----------------------------------------------------------------------
    // ETH-handling tests
    // -----------------------------------------------------------------------

    /// @notice The identity already holds the funds; an ACTION key sends 5 ETH to a receiver.
    function test_execute_accountFundedTransfer() public {
        ETHReceiver receiver = new ETHReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        vm.deal(address(aliceIdentity), 5 ether);

        // david is ACTION on aliceIdentity; ACTION + external target = auto-approve.
        uint256 davidPre = david.balance;
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute(address(receiver), 5 ether, "");

        assertEq(address(receiver).balance, 5 ether, "receiver should get the 5 ETH");
        assertEq(address(aliceIdentity).balance, 0, "identity drained");
        assertEq(kam.balance, 0, "module empty");
        assertEq(david.balance, davidPre, "caller wallet untouched");
    }

    /// @notice Caller attaches 5 ETH and asks the identity to send 5 ETH to a receiver.
    function test_execute_depositAndSpend() public {
        ETHReceiver receiver = new ETHReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        assertEq(address(aliceIdentity).balance, 0);

        vm.deal(david, 5 ether);
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute{ value: 5 ether }(address(receiver), 5 ether, "");

        assertEq(address(receiver).balance, 5 ether, "receiver should get the 5 ETH");
        assertEq(address(aliceIdentity).balance, 0, "identity drained");
        assertEq(kam.balance, 0, "module empty");
    }

    /// @notice Identity holds 4 ETH, caller adds 1, the identity sends 5 to a receiver.
    function test_execute_depositTopUpAndSpend() public {
        ETHReceiver receiver = new ETHReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        vm.deal(address(aliceIdentity), 4 ether);

        vm.deal(david, 1 ether);
        uint256 davidPre = david.balance;
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute{ value: 1 ether }(address(receiver), 5 ether, "");

        assertEq(address(receiver).balance, 5 ether, "receiver should get the 5 ETH");
        assertEq(address(aliceIdentity).balance, 0, "identity drained");
        assertEq(kam.balance, 0, "module empty");
        assertEq(david.balance, davidPre - 1 ether, "caller paid exactly 1 ETH");
    }

    /// @notice A CLAIM_SIGNER attaches 5 ETH on an external-target call. The call cannot
    ///         auto-approve, so the 5 ETH ends up in the identity and the request waits.
    function test_execute_pendingRequest_msgValueGoesToIdentity() public {
        ETHReceiver receiver = new ETHReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        vm.deal(carol, 5 ether);
        vm.prank(carol);
        uint256 executionId =
            IKeyExecutor(address(aliceIdentity)).execute{ value: 5 ether }(address(receiver), 5 ether, "");

        assertEq(address(aliceIdentity).balance, 5 ether, "identity received the 5 ETH");
        assertEq(kam.balance, 0, "module empty after execute()");
        assertEq(address(receiver).balance, 0, "receiver hasn't been paid yet");
        assertEq(executionId, 0, "first queued request");
    }

    /// @notice After a pending request is funded, an ACTION approver dispatches it; the
    ///         identity sends 5 ETH to the receiver from its own balance.
    function test_execute_pendingRequest_approveSendsFromIdentity() public {
        ETHReceiver receiver = new ETHReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        vm.deal(carol, 5 ether);
        vm.prank(carol);
        IKeyExecutor(address(aliceIdentity)).execute{ value: 5 ether }(address(receiver), 5 ether, "");
        assertEq(address(aliceIdentity).balance, 5 ether, "precondition: identity holds the 5 ETH");

        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).approve(0, true);

        assertEq(address(receiver).balance, 5 ether, "receiver should get the 5 ETH");
        assertEq(address(aliceIdentity).balance, 0, "identity drained");
        assertEq(kam.balance, 0, "module empty");
    }

    /// @notice Auto-approve runs but the target rejects ETH on receive. The caller's 5 ETH
    ///         stays in the identity (no refund to caller, no ETH stuck in the module).
    function test_execute_autoApprove_targetReverts_ethStaysInIdentity() public {
        RevertingReceiver bad = new RevertingReceiver();
        address kam = address(onchainidSetup.keyApprovalModule);

        vm.deal(david, 5 ether);
        vm.prank(david);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute{ value: 5 ether }(address(bad), 5 ether, "");

        assertEq(address(aliceIdentity).balance, 5 ether, "identity keeps the 5 ETH");
        assertEq(kam.balance, 0, "module empty");
        assertEq(address(bad).balance, 0, "reverting target received nothing");

        // The request is closed either way, but the outcome must not read as a success.
        KeyApprovalModule.Execution memory exec =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(exec.executed, "attempted and closed");
        assertFalse(exec.succeeded, "failed dispatch must not report success");
    }

    /// @notice A dispatch that lands records `succeeded`, so a reader can tell it apart from
    ///         the failed and rejected requests that also carry `executed`.
    function test_execute_successRecordsSucceeded() public {
        ETHReceiver receiver = new ETHReceiver();

        vm.deal(address(aliceIdentity), 1 ether);
        vm.prank(david);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(receiver), 1 ether, "");

        KeyApprovalModule.Execution memory exec =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(exec.executed, "attempted and closed");
        assertTrue(exec.succeeded, "dispatch landed");
    }

    /// @notice A rejected request closes without ever dispatching, so it is not a success either.
    function test_approve_rejectionIsNotASuccess() public {
        address proposer = makeAddr("proposerRejected");
        _grantProposer(proposer);

        vm.prank(proposer);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(0xBEEF), 0, "");

        // david holds ACTION, which is the approve gate for an external target.
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).approve(id, false);

        KeyApprovalModule.Execution memory exec =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(exec.executed, "rejection closes the request");
        assertFalse(exec.approved, "rejected");
        assertFalse(exec.succeeded, "never dispatched");
    }

    // -----------------------------------------------------------------------
    // PROPOSER purpose: queue gate
    // -----------------------------------------------------------------------

    /// @dev Add `who` as a PROPOSER key on alice's identity.
    function _grantProposer(address who) internal {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(who), KeyPurposes.PROPOSER, KeyTypes.ECDSA, abi.encodePacked(who), ""
        );
    }

    /// @notice A caller with no key cannot queue an execution.
    function test_execute_revertWhenCallerHasNoKey() public {
        address stranger = makeAddr("strangerNoKey");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Errors.SenderCannotPropose.selector, stranger));
        IKeyExecutor(address(aliceIdentity)).execute(address(0xBEEF), 0, "");
    }

    /// @notice A PROPOSER-only key can queue, but the request stays pending: PROPOSER
    ///         never satisfies the auto-approve ladder.
    function test_execute_proposerQueuesPendingRequest() public {
        address proposer = makeAddr("proposer");
        _grantProposer(proposer);

        vm.prank(proposer);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(0xBEEF), 0, "");

        KeyApprovalModule.Execution memory exec =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertEq(exec.to, address(0xBEEF));
        assertFalse(exec.approved, "PROPOSER alone must not auto-approve");
        assertFalse(exec.executed, "PROPOSER alone must not auto-execute");
    }

    /// @notice A PROPOSER-only key cannot self-approve its pending request: the approve
    ///         ladder still requires ACTION (external) or MANAGEMENT (self).
    function test_execute_proposerCannotSelfApprove() public {
        address proposer = makeAddr("proposer2");
        _grantProposer(proposer);

        vm.prank(proposer);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(0xBEEF), 0, "");

        vm.prank(proposer);
        vm.expectRevert(Errors.SenderDoesNotHaveActionKey.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);
    }

    /// @notice A PROPOSER-queued request runs after a purpose-appropriate approver
    ///         (ACTION for external targets) signs off.
    function test_execute_proposerQueuedRequestRunsAfterActionApproval() public {
        address proposer = makeAddr("proposer3");
        _grantProposer(proposer);

        ETHReceiver receiver = new ETHReceiver();
        vm.deal(address(aliceIdentity), 1 ether);

        vm.prank(proposer);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(receiver), 1 ether, "");

        // david is ACTION on alice's identity; approval dispatches the queued request.
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);

        assertEq(address(receiver).balance, 1 ether, "receiver paid out");
        assertEq(address(aliceIdentity).balance, 0, "identity drained");
    }

}

/// @notice Accepts any incoming ETH.
contract ETHReceiver {

    receive() external payable { }

}

/// @notice Rejects any incoming ETH.
contract RevertingReceiver {

    receive() external payable {
        revert("nope");
    }

}
