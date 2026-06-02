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
        IKeyExecutor(address(aliceIdentity)).execute{ value: 5 ether }(address(bad), 5 ether, "");

        assertEq(address(aliceIdentity).balance, 5 ether, "identity keeps the 5 ETH");
        assertEq(kam.balance, 0, "module empty");
        assertEq(address(bad).balance, 0, "reverting target received nothing");
    }

    // -----------------------------------------------------------------------
    // Approval-state machine
    // -----------------------------------------------------------------------

    /// @notice Approve(id, true) twice → second reverts (RequestAlreadyExecuted).
    function test_approve_doubleApprove_reverts() public {
        // Queue a self-targeted call (requires MANAGEMENT to auto-approve).
        // carol has CLAIM_SIGNER only, so this self-target waits for approve.
        bytes memory addKey = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("k"), KeyPurposes.ACTION, KeyTypes.ECDSA
        );
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKey);

        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);

        vm.prank(alice);
        vm.expectRevert(Errors.RequestAlreadyExecuted.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);
    }

    /// @notice Approve(id, false) marks closed; further approve reverts.
    function test_approve_rejectThenApprove_reverts() public {
        // queue
        bytes memory addKey = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("k2"), KeyPurposes.ACTION, KeyTypes.ECDSA
        );
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKey);

        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).approve(id, false);

        vm.prank(alice);
        vm.expectRevert(Errors.RequestAlreadyExecuted.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);
    }

    /// @notice Approving an id ≥ current nonce → InvalidRequestId.
    function test_approve_invalidRequestId_reverts() public {
        vm.prank(alice);
        vm.expectRevert(Errors.InvalidRequestId.selector);
        IKeyExecutor(address(aliceIdentity)).approve(99, true);
    }

    /// @notice Self-targeted approve from a non-MANAGEMENT caller → reverts.
    function test_approve_selfTarget_nonManagement_reverts() public {
        // carol queues a self call; carol does NOT have MANAGEMENT, so even she can't approve it.
        bytes memory addKey = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("k3"), KeyPurposes.ACTION, KeyTypes.ECDSA
        );
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKey);

        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);
    }

    /// @notice External-target approve requires ACTION (not just CLAIM_SIGNER).
    function test_approve_externalTarget_nonAction_reverts() public {
        ETHReceiver receiver = new ETHReceiver();
        // carol queues an external call (CLAIM_SIGNER cannot auto-approve external).
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(receiver), 0, "");

        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveActionKey.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);
    }

    /// @notice Direct EOA call to module bypassing the account fallback yields _msgSender
    ///         = the EOA, which has no purpose on the (zero-storage) state; auto-approval fails.
    function test_directModuleCall_byEOA_isNotAutoApproved() public {
        KeyApprovalModule kam = onchainidSetup.keyApprovalModule;
        // Direct call: msg.sender == david, no fallback wrapping, no trailer.
        vm.prank(david);
        // Since the account here is david (an EOA), the IERC734 call to keyHasPurpose reverts —
        // david isn't a contract. We just assert the call reverts cleanly.
        vm.expectRevert();
        kam.execute(address(0xDEAD), 0, "");
    }

    /// @notice canAutoApprove externally with account != msg.sender reverts.
    function test_canAutoApprove_crossAccount_reverts() public {
        KeyApprovalModule kam = onchainidSetup.keyApprovalModule;
        vm.expectRevert(Errors.UnauthorizedPolicyQuery.selector);
        kam.canAutoApprove(address(aliceIdentity), ClaimSignerHelper.addressToKey(alice), address(0), "");
    }

    /// @notice getExecutionData round-trips a queued (but not yet executed) request.
    function test_getExecutionData_roundtrip() public {
        ETHReceiver receiver = new ETHReceiver();
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(receiver), 5 ether, hex"01");

        KeyApprovalModule kam = onchainidSetup.keyApprovalModule;
        KeyApprovalModule.Execution memory e = kam.getExecutionData(address(aliceIdentity), id);
        assertEq(e.to, address(receiver));
        assertEq(e.value, 5 ether);
        assertEq(e.data, hex"01");
        assertEq(e.executed, false);
        assertEq(e.approved, false);
    }

    /// @notice CLAIM_ADDER cannot remove an existing claim — approval path requires ACTION
    ///         on self-call (MANAGEMENT-implied) for the queued request.
    function test_execute_claimAdder_selfRemoveClaim_queuedThenRejected() public {
        // Grant bob CLAIM_ADDER on aliceIdentity.
        vm.prank(alice);
        aliceIdentity.addKey(ClaimSignerHelper.addressToKey(bob), KeyPurposes.CLAIM_ADDER, KeyTypes.ECDSA);

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), 666);
        bytes memory removeClaim = abi.encodeWithSignature("removeClaim(bytes32)", claimId);

        // CLAIM_ADDER + self + removeClaim is NOT auto-approved → queued.
        vm.prank(bob);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, removeClaim);

        KeyApprovalModule kam = onchainidSetup.keyApprovalModule;
        assertFalse(kam.getExecutionData(address(aliceIdentity), id).executed);
    }

    /// @notice Pins the `KeyApprovalModule.approve` rejection path: after `approve(id, false)`,
    ///         the queue entry must have `approved == false` and `executed == true`.
    function test_approve_rejected_postState() public {
        bytes memory addKey = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("k-rej"), KeyPurposes.ACTION, KeyTypes.ECDSA
        );
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKey);

        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).approve(id, false);

        KeyApprovalModule.Execution memory e =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(e.executed, "rejected entry must be marked executed");
        assertFalse(e.approved, "rejected entry must have approved=false");
    }

    /// @notice Pins the ETH push-back guard. A caller that has no payable receive function
    ///         cannot receive the bounced msg.value; the module must revert with
    ///         `ReturnToAccountFailed` rather than silently swallowing the failed call.
    function test_execute_directCall_pushBackFails_revertsCleanly() public {
        NoReceiver bad = new NoReceiver();
        vm.deal(address(this), 1);
        vm.expectRevert(Errors.ReturnToAccountFailed.selector);
        bad.callExecute{ value: 1 }(onchainidSetup.keyApprovalModule, address(0));
    }

    /// @notice Pins the `execution.approved = true` write inside `_runApproved` at
    ///         `KeyApprovalModule.sol:212`. After an auto-approved execution the queue entry
    ///         MUST have both `executed == true` AND `approved == true`. The existing
    ///         rejection-path test (`test_approve_rejected_postState`) covers `approved ==
    ///         false` after rejection; this one is the symmetric positive read after a
    ///         successful run.
    function test_autoApprovedExecution_setsApprovedTrue() public {
        // david holds ACTION on aliceIdentity → external call auto-approves.
        Counter c = new Counter();
        vm.prank(david);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(address(c), 0, abi.encodeCall(Counter.tick, ()));
        assertEq(c.count(), 1, "auto-approval should have run the call");

        KeyApprovalModule.Execution memory e =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(e.executed, "auto-approved entry must be marked executed");
        assertTrue(e.approved, "auto-approved entry must have approved=true");
    }

}

/// @dev Tiny external target used by the auto-approval kill test.
contract Counter {

    uint256 public count;

    function tick() external {
        count++;
    }

}

/// @dev A contract with no payable receive/fallback. Used to force the ETH push-back path
///      inside `KeyApprovalModule.execute` to fail at the EVM level.
contract NoReceiver {

    function callExecute(KeyApprovalModule module, address to) external payable {
        module.execute{ value: msg.value }(to, 0, "");
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
