// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { IAccount } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    Execution,
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { SmartAccount } from "contracts/SmartAccount.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { ClaimSignerHelper } from "./helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";
import { MockStockECDSAValidator } from "./mocks/MockStockECDSAValidator.sol";

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

        (,, bytes32 storedKey) = IERC734(address(aliceIdentity)).getKey(evilKey);
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
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
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
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
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
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // Register a brand-new key. The keyHash must commit to its signer bytes, so derive it
        // from a signer address and register via the data-carrying addKeyWithData entry point.
        address newSigner = makeAddr("new-action-signer");
        bytes memory newSignerData = abi.encodePacked(newSigner);
        bytes32 newKey = keccak256(newSignerData);
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
            newKey,
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            newSignerData,
            bytes("")
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);

        (,, bytes32 storedKey) = IERC734(address(aliceIdentity)).getKey(newKey);
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
        MockStockECDSAValidator validator = new MockStockECDSAValidator();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(alice));
        // Validators don't need an ERC 734 purpose. We add one anyway so we can check
        // that uninstall cleans it up.
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(validator))),
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            abi.encodePacked(address(validator)),
            ""
        );
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
        (,, bytes32 storedKey) = IERC734(address(aliceIdentity)).getKey(keccak256(abi.encodePacked(address(validator))));
        assertEq(storedKey, bytes32(0), "auto revoke should clear the module's key entry");
    }

    /// An ACTION key shouldn't be able to uninstall a module — uninstall is MANAGEMENT only.
    function test_uninstallModule_byActionKey_reverts() public {
        MockStockECDSAValidator validator = new MockStockECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(alice));

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
        (,, bytes32 moduleStoredKey) = IERC734(address(aliceIdentity)).getKey(keccak256(abi.encodePacked(kam)));
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

    /// Fallback handlers register per selector, so KAM holds four installs backed by one
    /// MODULE key. Dropping a single read-only selector must not strip that key: the
    /// executor install and the other handlers still rely on it.
    function test_uninstallModule_fallbackSelector_keepsModulePurposes() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        bytes32 moduleKey = keccak256(abi.encodePacked(kam));

        vm.prank(alice);
        aliceIdentity.uninstallModule(
            MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.getCurrentNonce.selector)
        );

        // The selector is unwired...
        vm.expectRevert();
        IKeyExecutor(address(aliceIdentity)).getCurrentNonce();

        // ...but the module keeps its MANAGEMENT registration and stays an executor.
        assertTrue(
            IERC734(address(aliceIdentity)).keyHasPurpose(moduleKey, KeyPurposes.MANAGEMENT),
            "fallback uninstall must not strip the module's key"
        );
        assertTrue(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, kam, ""), "executor install should be untouched"
        );

        // The remaining execute handler still dispatches through the executor.
        Counter counter = new Counter();
        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));
        assertEq(counter.count(), 1, "executor dispatch should keep working after the selector drop");
    }

    /// When the module's key is the only MANAGEMENT holder, the old strip-everything path
    /// hit `CannotRemoveLastManagementKey` and the handler could not be uninstalled at all.
    /// Fallback uninstalls no longer touch keys, so the drop goes through.
    function test_uninstallModule_fallbackSelector_whenModuleIsLastManagement_succeeds() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        bytes32 aliceKey = keccak256(abi.encodePacked(alice));

        // Leave KAM as the sole MANAGEMENT key.
        vm.prank(alice);
        aliceIdentity.removeKey(aliceKey, KeyPurposes.MANAGEMENT);

        vm.prank(kam);
        aliceIdentity.uninstallModule(
            MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.getCurrentNonce.selector)
        );

        assertTrue(
            IERC734(address(aliceIdentity)).keyHasPurpose(keccak256(abi.encodePacked(kam)), KeyPurposes.MANAGEMENT),
            "the last MANAGEMENT key survives the selector drop"
        );
    }

    /// @notice A MANAGEMENT-purpose module cannot use its onUninstall callback to grant itself a
    ///         key. The account strips the module's purposes before running onUninstall, so by the
    ///         time the callback re-enters addKey the module holds no MANAGEMENT and the grant fails.
    ///         (The base runs onUninstall best-effort, so the uninstall itself still completes; the
    ///         property that matters is that the evil key is never written.)
    function test_uninstallModule_reentrantOnUninstall_cannotGrantKey() public {
        ReentrantUninstaller evil = new ReentrantUninstaller();

        // Install as an executor holding MANAGEMENT (the dangerous shape KAM has).
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(evil), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(evil))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(evil)),
            ""
        );

        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, address(evil), "");
        vm.stopPrank();

        // The attacker key was never granted: the re-entrant addKeyWithData ran without MANAGEMENT.
        (,, bytes32 storedEvil) = IERC734(address(aliceIdentity)).getKey(evil.evilKey());
        assertEq(storedEvil, bytes32(0), "re-entrant onUninstall must not grant a key");

        // And the module's own MANAGEMENT key is gone.
        (,, bytes32 storedModule) = IERC734(address(aliceIdentity)).getKey(keccak256(abi.encodePacked(address(evil))));
        assertEq(storedModule, bytes32(0), "uninstalled module keeps no MANAGEMENT");
    }

    /// How you upgrade a module with ERC 7579. Uninstall the old one, install the new one.
    function test_uninstallModule_then_reinstall_upgradePath() public {
        MockStockECDSAValidator v1 = new MockStockECDSAValidator();
        MockStockECDSAValidator v2 = new MockStockECDSAValidator();

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(v1), abi.encodePacked(alice));
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(v1), "");
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(v2), abi.encodePacked(alice));
        vm.stopPrank();

        assertFalse(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(v1), ""),
            "old validator should be uninstalled"
        );
        assertTrue(
            aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(v2), ""), "new validator should be installed"
        );
    }

    // -----------------------------------------------------------------------
    // Executor authorization — `_execute` purpose-checks executor callers with
    // one built-in rule: self-target needs MANAGEMENT, any other target needs
    // ACTION, and no dispatched call may land on one of the account's own
    // modules. No policy module is consulted.
    // -----------------------------------------------------------------------

    /// @notice An executor whose key holds CLAIM_SIGNER CANNOT dispatch `addClaim` on self.
    ///         There is no self-call exemption in `_requireClaimKey`, so the module enforces the
    ///         purpose check against the calldata-tail caller — which is the account itself in the
    ///         executor flow, and the account does not hold a CLAIM_SIGNER key.
    function test_executeFromExecutor_claimSignerExecutor_cannotAddClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // Self-issued claims now require a valid signature from one of the identity's CLAIM_SIGNER keys.
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: bytes("payload") });
        bytes memory signature =
            ClaimSignerHelper.signClaim(carolPk, carol, address(aliceIdentity), address(aliceIdentity), 42, data);

        bytes memory addClaimData = abi.encodeCall(
            IERC735.addClaim, (uint256(42), uint256(1), address(aliceIdentity), signature, data, string(""))
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert();
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor whose key holds CLAIM_SIGNER CANNOT dispatch `removeClaim` on self.
    ///         Same reason as above — the self-call exemption is gone, and the account itself
    ///         is not a CLAIM_SIGNER on its own registry.
    function test_executeFromExecutor_claimSignerExecutor_cannotRemoveClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // aliceClaim666 already exists in the fixture. Use its claimId.
        bytes32 claimId = keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic));
        bytes memory removeClaimData = abi.encodeWithSignature("removeClaim(bytes32)", claimId);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), removeClaimData);

        vm.expectRevert();
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A CLAIM_SIGNER executor MUST NOT escalate to other self-selectors like `addKey`.
    function test_executeFromExecutor_claimSignerExecutor_cannotAddKeyOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        bytes32 evilKey = keccak256("evil-mgmt-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor whose key holds CLAIM_ADDER CANNOT dispatch `addClaim` on self.
    ///         Same reason as the CLAIM_SIGNER variants — there is no self-call exemption, so the
    ///         account being the calldata-tail caller does not skip the purpose check.
    function test_executeFromExecutor_claimAdderExecutor_cannotAddClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_ADDER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // Self-issued claims now require a valid signature from one of the identity's CLAIM_SIGNER keys.
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: bytes("payload") });
        bytes memory signature =
            ClaimSignerHelper.signClaim(carolPk, carol, address(aliceIdentity), address(aliceIdentity), 43, data);

        bytes memory addClaimData = abi.encodeCall(
            IERC735.addClaim, (uint256(43), uint256(1), address(aliceIdentity), signature, data, string(""))
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert();
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A CLAIM_ADDER executor MUST NOT be able to dispatch `removeClaim` on self.
    function test_executeFromExecutor_claimAdderExecutor_cannotRemoveClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_ADDER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        bytes32 claimId = keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic));
        bytes memory removeClaimData = abi.encodeWithSignature("removeClaim(bytes32)", claimId);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), removeClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice Ernest's r3230643398 shape: a CLAIM_ADDER-only key must not be able to dispatch
    ///         an arbitrary external call. The executor-as-key path mirrors what `_validateUserOp`
    ///         would do for a UserOp signer with the same purpose.
    function test_executeFromExecutor_claimAdderExecutor_cannotCallExternal() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_ADDER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice BATCH path: any non-claim selector in a CLAIM_SIGNER's batch poisons the whole batch.
    function test_executeFromExecutor_claimSignerExecutor_batchMixedSelectors_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeCall(
                IERC735.addClaim,
                (
                    uint256(100),
                    uint256(1),
                    address(aliceIdentity),
                    bytes(""),
                    Structs.ClaimData({ issuedAt: 0, validUntil: 0, payload: bytes("payload") }),
                    string("")
                )
            )
        });
        batch[1] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
            )
        });

        bytes32 batchMode = bytes32(uint256(0x01) << 248);
        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), batchMode, abi.encode(batch));
    }

    /// @notice Short calldata guard: a self-targeted SINGLE payload with no selector is rejected.
    function test_executeFromExecutor_selfTarget_calldataTooShort_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // SINGLE layout: target(20) + value(32) — exactly 52 bytes, no inner data at all.
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0));

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A malformed SINGLE payload (length < 52) is rejected. The account's per-call guard
    ///         skips a payload too short to carry a target+value and lets the base ERC-7579
    ///         dispatcher reject the malformed layout, so the call still reverts.
    function test_executeFromExecutor_singleCalldata_lengthBelow52_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        // Truncated payload — only the 20-byte target, no value field.
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity));

        vm.expectRevert();
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    // -----------------------------------------------------------------------
    // Strict-rule tests — the account applies its built-in rule to executor
    // callers (self → MANAGEMENT, else → ACTION) and consults no policy module.
    // -----------------------------------------------------------------------

    /// @notice The account consults no policy module: the built-in rule is the only rule.
    ///         Even with an always-approve policy wired as the `execute` fallback handler,
    ///         a keyless executor stays unauthorized.
    function test_executeFromExecutor_policyModuleIsNotConsulted() public {
        // Replace the real handler with one that would approve everything, if asked.
        address kam = address(onchainidSetup.keyApprovalModule);
        vm.startPrank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        AlwaysApprovePolicy approveAll = new AlwaysApprovePolicy();
        aliceIdentity.installModule(
            MODULE_TYPE_FALLBACK, address(approveAll), abi.encodePacked(IKeyExecutor.execute.selector)
        );

        // Install the executor but do not give it any key. If the account asked the policy,
        // this call would go through; the built-in rule rejects it.
        TestExecutor testExec = new TestExecutor();
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice Ernest's r3421876946 happy path: an ACTION executor targeting an external
    ///         contract. The built-in rule authorizes it.
    function test_executeFromExecutor_path_actionOnExternal_succeeds() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "ACTION executor on external target should be authorized");
    }

    /// @notice A CLAIM_SIGNER-only executor CANNOT dispatch `addClaim` on self: the built-in
    ///         rule requires MANAGEMENT for self-targets, with no claim-selector exception.
    function test_executeFromExecutor_strictRule_claimSignerSelfFails() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(testExec))),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(testExec)),
            ""
        );
        vm.stopPrank();

        bytes memory addClaimData = abi.encodeCall(
            IERC735.addClaim,
            (
                uint256(202),
                uint256(1),
                address(aliceIdentity),
                bytes(""),
                Structs.ClaimData({ issuedAt: 0, validUntil: 0, payload: bytes("payload") }),
                string("")
            )
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    // -----------------------------------------------------------------------
    // ERC-4337 _validateUserOp tests — exercises the full AA path that
    // executeFromExecutor bypasses. We impersonate the canonical EntryPoint
    // (ENTRYPOINT_V09) and call validateUserOp directly. Two things checked:
    //   1) a well-formed UserOp from an ACTION key → SUCCESS
    //   2) the same UserOp but targeting a self-call (e.g. addKey) → FAIL
    //      because ACTION isn't enough for self-modification.
    // -----------------------------------------------------------------------

    /// @notice The canonical ERC-4337 v0.9 EntryPoint address. `Account.entryPoint()`
    ///         returns this constant, and `validateUserOp` only accepts calls from it.
    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    /// @dev Pack the validator address into the top 20 bytes of `nonce`, as required
    ///      by OZ's `_extractUserOpValidator`. Lower 12 bytes are the actual nonce.
    function _packNonce(address validator, uint96 seq) internal pure returns (uint256) {
        return (uint256(uint160(validator)) << 96) | uint256(seq);
    }

    /// @dev Build a minimal PackedUserOperation for `aliceIdentity` calling
    ///      `target.callData` via the standard execute() pathway, signed by `david`
    ///      (who has ACTION on the identity in OnchainIDSetup).
    function _buildAndSignUserOp(address target, bytes memory innerCall)
        internal
        view
        returns (PackedUserOperation memory userOp, bytes32 userOpHash)
    {
        // SINGLE-mode execute payload: target(20) || value(32) || data
        bytes memory executionCalldata = abi.encodePacked(target, uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);

        userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(onchainidSetup.signatureValidator), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });

        // For test purposes any deterministic hash works; the validator only checks the
        // signature against this hash. `_signableUserOpHash` returns it unchanged by default.
        userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));

        // david signs (he holds ACTION on aliceIdentity via the OnchainIDSetup fixture)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        bytes memory ecdsaSig = abi.encodePacked(r, s, v);
        bytes memory signer = abi.encodePacked(david);
        userOp.signature = abi.encode(signer, ecdsaSig);
    }

    /// @notice Happy path: ACTION key signs a UserOp that calls an external target.
    ///         All three gates pass (validator + ACTION purpose + per-target rule).
    function test_validateUserOp_actionKey_externalTarget_succeeds() public {
        Counter counter = new Counter();
        bytes memory innerCall = abi.encodeCall(Counter.increment, ());

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildAndSignUserOp(address(counter), innerCall);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS, "ACTION + external target must succeed");
    }

    /// @notice The per-target rule fires: an ACTION-only key cannot self-target
    ///         a privileged selector like addKey. The signature is cryptographically
    ///         valid, but step 2 of _validateUserOp rejects it.
    /// @notice The fixture installs `ERC734Validator`, which scopes by target/selector. `david`
    ///         holds ACTION inside it, so a self-target `addKey` (MANAGEMENT-grade) is rejected
    ///         at the validator. Scoping lives in the validator, not the account.
    function test_validateUserOp_actionSigner_selfTargetAddKey_rejectedByValidator() public {
        bytes memory innerCall = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildAndSignUserOp(address(aliceIdentity), innerCall);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(
            result,
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "ACTION signer must not self-target addKey; the scoping validator blocks it"
        );
    }

    /// @notice A validator that is installed but NOT granted ACTION cannot authorize
    ///         a userOp against an external target. Under "validators-as-keys" the
    ///         per-target rule is checked against `hashAddress(validator)`, not
    ///         against the recovered signer, so an unauthorized validator fails
    ///         even when its signature is cryptographically valid.
    /// @dev Documents the same trade-off from the validator-authorization angle. Previously
    ///      the account required the installed validator to hold an ACTION purpose to act.
    ///      That check moved out of the account: the OZ base only dispatches to an installed
    ///      validator, and the validator itself decides authorization. So an installed stock
    ///      validator with a signer it accepts now validates a plain external call without the
    ///      account granting it any purpose. Scoping validators still gate this internally.
    function test_validateUserOp_installedStockValidator_noAccountPurpose_nowPasses() public {
        // Install a fresh stock validator without granting it any purpose. Seed its signer
        // registry with `david` so the signature passes the validator's own check.
        MockStockECDSAValidator rogue = new MockStockECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(rogue), abi.encodePacked(david));

        Counter counter = new Counter();
        bytes memory innerCall = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(rogue), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        // MockStockECDSAValidator takes a raw 65-byte ECDSA signature (no signer wrapper).
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(
            result,
            ERC4337Utils.SIG_VALIDATION_SUCCESS,
            "account no longer requires a purpose grant: the installed validator decides"
        );
    }

    /// @notice ERC-1271 dispatch. The account routes `isValidSignature` to the validator named
    ///         by the first 20 bytes of the outer signature (OZ `_extractSignatureValidator`),
    ///         then returns whatever magic value the validator produces.
    function test_isValidSignature_routesToValidatorByModulePrefix() public {
        (address signer, uint256 signerPk) = makeAddrAndKey("erc1271-signer");
        MockStockECDSAValidator validator = new MockStockECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(signer));

        bytes32 digest = keccak256("erc1271-dispatch");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory outerSig = abi.encodePacked(address(validator), abi.encodePacked(r, s, v));

        assertEq(
            IERC1271(address(aliceIdentity)).isValidSignature(digest, outerSig),
            IERC1271.isValidSignature.selector,
            "account must route isValidSignature to the prefixed validator"
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

/// @notice Interface fragment for the account's `addKeyWithData` (defined on KeyManager, not IERC734).
interface IAddKeyWithData {

    function addKeyWithData(
        bytes32 key,
        uint256 purpose,
        uint256 keyType,
        bytes memory signerData,
        bytes memory clientData
    ) external;

}

/// @notice Malicious executor that, during its own onUninstall, tries to register a fresh attacker
///         key with MANAGEMENT. If the account still leaves this module holding MANAGEMENT when it
///         runs onUninstall, the grant lands. Stripping the module's purposes first blocks it.
contract ReentrantUninstaller is IERC7579Module {

    address public constant ATTACKER = address(0xBADBEEF);

    function evilKey() external pure returns (bytes32) {
        return keccak256(abi.encodePacked(ATTACKER));
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function onInstall(bytes calldata) external pure { }

    function onUninstall(bytes calldata) external {
        // msg.sender is the account. addKeyWithData carries the signer bytes, so it actually
        // registers a usable key — gated by MANAGEMENT on the account (which this module held).
        IAddKeyWithData(msg.sender)
            .addKeyWithData(
                keccak256(abi.encodePacked(ATTACKER)),
                KeyPurposes.MANAGEMENT,
                KeyTypes.ECDSA,
                abi.encodePacked(ATTACKER),
                ""
            );
    }

}

/// @notice ERC-7579 FALLBACK module whose `canAutoApprove` returns true for any input.
///         Used to prove that the account does NOT consult a policy module: wiring this
///         handler must not authorize a keyless executor.
contract AlwaysApprovePolicy is IERC7579Module {

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    function onInstall(bytes calldata) external pure { }
    function onUninstall(bytes calldata) external pure { }

    function canAutoApprove(address, bytes32, address, bytes calldata) external pure returns (bool) {
        return true;
    }

}
