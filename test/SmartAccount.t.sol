// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { SmartAccount } from "contracts/SmartAccount.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ECDSAValidator } from "contracts/modules/validators/ECDSAValidator.sol";

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

    /// You can't remove the last MANAGEMENT key. If you could, nothing would satisfy
    /// `onlyManager` anymore and the identity would be stuck.
    ///
    /// The fixture (`OnchainIDSetup`) installs `KeyApprovalModule` and gives it
    /// MANAGEMENT so it can dispatch self targeted calls. The protocol doesn't pin
    /// it there. Every identity just gets whatever module list the caller hands the
    /// factory. We strip that registration first so alice is the only MANAGEMENT key
    /// left, then we check that the guard fires.
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

    // Module uninstall tests. We don't pin any module on the account. The promise we
    // care about is: taking a module off can only drop rights, never add new ones.
    // The tests below check that.

    /// MANAGEMENT can uninstall a module the same way it can install one, and the
    /// module's ERC 734 entry is cleaned up on the way out.
    function test_uninstallModule_byManagement_succeeds() public {
        // The fixture only installs the queue module, so we add a fresh validator here
        // and own its lifecycle for this test.
        ECDSAValidator validator = new ECDSAValidator();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");
        // Validators don't need an ERC 734 purpose. We add one anyway so we can check
        // that uninstall cleans it up.
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(validator))), KeyPurposes.ACTION, KeyTypes.ECDSA);
        vm.stopPrank();

        assertTrue(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "precondition: validator installed"
        );

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        assertFalse(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator), ""),
            "validator should be uninstalled"
        );
        (,, bytes32 storedKey) = aliceIdentity.getKey(keccak256(abi.encodePacked(address(validator))));
        assertEq(storedKey, bytes32(0), "auto revoke should clear the module's key entry");
    }

    /// An ACTION key shouldn't be able to uninstall a module — uninstall is MANAGEMENT only.
    function test_uninstallModule_byActionKey_reverts() public {
        ECDSAValidator validator = new ECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), "");

        // david is ACTION on alice's identity (set up in OnchainIDSetup), not MANAGEMENT.
        vm.prank(david);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");
    }

    /// The important one. Once we uninstall KeyApprovalModule (the executor and its three
    /// fallback handlers) the legacy ERC 734 execute / approve ABI on the identity stops
    /// working. What MUST NOT happen is that the remaining keys suddenly gain new powers.
    function test_uninstallModule_keyApprovalModule_noPermissionBypass() public {
        address kam = address(onchainidSetup.keyApprovalModule);

        // The executor side first. For executors, deInitData is empty.
        vm.startPrank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, kam, "");
        // Then the three fallback entries. deInitData here is the selector.
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.approve.selector));
        aliceIdentity.uninstallModule(
            MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.getCurrentNonce.selector)
        );
        vm.stopPrank();

        // The MANAGEMENT entry that was registered against the module's address is gone.
        (,, bytes32 moduleStoredKey) = aliceIdentity.getKey(keccak256(abi.encodePacked(kam)));
        assertEq(moduleStoredKey, bytes32(0), "queue module's MANAGEMENT key should be revoked");

        // Calling the legacy ABI on the identity now reverts. No fallback handler is wired up.
        vm.prank(david);
        vm.expectRevert();
        IKeyExecutor(address(aliceIdentity)).execute(address(0), 0, "");

        // david (ACTION) can't reach addKey on the identity directly. He didn't get any new
        // power from the uninstall.
        bytes32 newKey = keccak256("post-uninstall-action-key");
        vm.prank(david);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        aliceIdentity.addKey(newKey, KeyPurposes.ACTION, KeyTypes.ECDSA);

        // Same story for carol (CLAIM_SIGNER). Self targeted privileged ops still need MANAGEMENT.
        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        aliceIdentity.addKey(newKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
    }

    /// How you upgrade a module with ERC 7579. Uninstall the old one, install the new one.
    function test_uninstallModule_then_reinstall_upgradePath() public {
        ECDSAValidator v1 = new ECDSAValidator();
        ECDSAValidator v2 = new ECDSAValidator();

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(v1), "");
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(v1), "");
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(v2), "");
        vm.stopPrank();

        assertFalse(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(v1), ""),
            "old validator should be uninstalled"
        );
        assertTrue(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(v2), ""), "new validator should be installed"
        );
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
