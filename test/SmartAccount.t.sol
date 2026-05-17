// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { SmartAccount } from "contracts/SmartAccount.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

import { ClaimSignerHelper } from "./helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";

/// @notice Coverage for the SmartAccount execution surface and ERC-734 purpose invariants.
contract SmartAccountTest is OnchainIDSetup {

    /// @notice ACTION key calls execute() on an external target; the queue module auto-approves.
    function test_execute_externalCall_byActionKey_autoApproves() public {
        Counter counter = new Counter();

        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));

        assertEq(counter.count(), 1, "auto-approved external call should run");
    }

    /// @notice A CLAIM_SIGNER key must not be able to call self-targeted `addKey` through
    ///         execute(): the queue module's auto-approval is bounded to claim selectors only,
    ///         and explicit approval of a self-call requires MANAGEMENT.
    function test_execute_selfCall_byClaimSigner_does_not_escalate_to_addKey() public {
        bytes32 evilKey = keccak256("evil-management-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );

        // carol is a CLAIM_SIGNER on aliceIdentity.
        vm.prank(carol);
        IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKeyData);

        (,, bytes32 storedKey) = aliceIdentity.getKey(evilKey);
        assertEq(storedKey, bytes32(0), "CLAIM_SIGNER must not escalate to MANAGEMENT via execute/addKey");
    }

    /// @notice Removing the only MANAGEMENT key on an identity must revert — otherwise the
    ///         identity becomes unrecoverable (no caller would satisfy `onlyManager`).
    /// @dev The auto-installed KeyApprovalModule also registers itself as a MANAGEMENT key
    ///      (so it can dispatch self-targeted calls through `executeFromExecutor`). To get
    ///      down to a single MANAGEMENT key we first remove the module's registration.
    function test_removeKey_lastManagementKey_reverts() public {
        bytes32 aliceKey = keccak256(abi.encodePacked(alice));
        bytes32 moduleKey = keccak256(abi.encodePacked(address(onchainidSetup.keyApprovalModule)));

        // Strip the module's MANAGEMENT registration so alice is the only one left.
        vm.prank(alice);
        aliceIdentity.removeKey(moduleKey, KeyPurposes.MANAGEMENT);

        vm.prank(alice);
        vm.expectRevert(Errors.CannotRemoveLastManagementKey.selector);
        aliceIdentity.removeKey(aliceKey, KeyPurposes.MANAGEMENT);
    }

    // -----------------------------------------------------------------------
    // Executor-bypass tests — executor's address is an ERC-734 key
    // -----------------------------------------------------------------------

    /// @notice An installed executor with no key registration cannot dispatch — its
    ///         `keccak256(abi.encodePacked(address))` is not in the registry, so the per-target
    ///         purpose check fails.
    function test_executeFromExecutor_unregisteredExecutor_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        // No addKey for the executor's address — it has no purpose on this account.

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor granted ACTION purpose can dispatch external calls.
    function test_executeFromExecutor_actionExecutor_canCallExternal() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.ACTION, KeyTypes.ECDSA);
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "ACTION executor should dispatch external");
    }

    /// @notice An executor granted ACTION purpose CANNOT dispatch a self-targeted call.
    ///         Self-modification requires the executor's key to hold MANAGEMENT.
    function test_executeFromExecutor_actionExecutor_cannotCallSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.ACTION, KeyTypes.ECDSA);
        vm.stopPrank();

        bytes32 evilKey = keccak256("evil-management-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor granted MANAGEMENT purpose can dispatch self-targeted calls.
    function test_executeFromExecutor_managementExecutor_canCallSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
        vm.stopPrank();

        bytes32 newKey = keccak256("new-action-key");
        bytes memory addKeyData =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", newKey, KeyPurposes.ACTION, KeyTypes.ECDSA);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);

        (,, bytes32 storedKey) = aliceIdentity.getKey(newKey);
        assertEq(storedKey, newKey, "MANAGEMENT executor should register a new key");
    }

}

/// @notice Minimal ERC-7579 executor used to test the account's purpose-based gate.
contract TestExecutor is IERC7579Module {

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function onInstall(bytes calldata) external pure { }
    function onUninstall(bytes calldata) external pure { }

    function callExecuteFromExecutor(address account, bytes32 mode, bytes calldata executionCalldata)
        external
        returns (bytes[] memory)
    {
        return IERC7579Execution(account).executeFromExecutor(mode, executionCalldata);
    }

}

/// @notice Simple counter used as an external target in execute() tests.
contract Counter {

    uint256 public count;

    function increment() external {
        count++;
    }

}
