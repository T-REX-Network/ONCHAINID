// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { IAccount } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
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
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
import { Structs } from "contracts/storage/Structs.sol";

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
        ERC7579Signature validator = new ERC7579Signature();
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
        ERC7579Signature validator = new ERC7579Signature();
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
        ERC7579Signature v1 = new ERC7579Signature();
        ERC7579Signature v2 = new ERC7579Signature();

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

    // -----------------------------------------------------------------------
    // Selector-aware authorization — `_isKeyAuthorizedToCallTarget`.
    //
    // The helper is shared by `_validateUserOp` (AA path) and `executeFromExecutor`
    // (executor path), so every executor-as-key test below also covers the AA-path
    // rule for the same caller. The rule table mirrors `KeyApprovalModule._canAutoApprove`:
    //   MANAGEMENT: anything; ACTION: external only; CLAIM_SIGNER on self: addClaim
    //   / removeClaim; CLAIM_ADDER on self: addClaim.
    // -----------------------------------------------------------------------

    /// @notice An executor whose key holds CLAIM_SIGNER can dispatch `addClaim` on self.
    function test_executeFromExecutor_claimSignerExecutor_canAddClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
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

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor whose key holds CLAIM_SIGNER can dispatch `removeClaim` on self.
    function test_executeFromExecutor_claimSignerExecutor_canRemoveClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        // aliceClaim666 already exists in the fixture. Use its claimId.
        bytes32 claimId = keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic));
        bytes memory removeClaimData = abi.encodeWithSignature("removeClaim(bytes32)", claimId);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), removeClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A CLAIM_SIGNER executor MUST NOT escalate to other self-selectors like `addKey`.
    function test_executeFromExecutor_claimSignerExecutor_cannotAddKeyOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        bytes32 evilKey = keccak256("evil-mgmt-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor whose key holds CLAIM_ADDER can dispatch `addClaim` on self,
    ///         provided the claim carries a valid signature from a CLAIM_SIGNER on the identity.
    function test_executeFromExecutor_claimAdderExecutor_canAddClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_ADDER, KeyTypes.ECDSA);
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

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A CLAIM_ADDER executor MUST NOT be able to dispatch `removeClaim` on self.
    function test_executeFromExecutor_claimAdderExecutor_cannotRemoveClaimOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_ADDER, KeyTypes.ECDSA);
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
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_ADDER, KeyTypes.ECDSA);
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice BATCH path: a CLAIM_SIGNER executor can dispatch `[addClaim, removeClaim]` on self.
    function test_executeFromExecutor_claimSignerExecutor_batchAddRemoveOnSelf() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        // Self-issued claims now require a valid signature from one of the identity's CLAIM_SIGNER keys.
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: bytes("payload") });
        bytes memory signature =
            ClaimSignerHelper.signClaim(carolPk, carol, address(aliceIdentity), address(aliceIdentity), 99, data);

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeCall(
                IERC735.addClaim, (uint256(99), uint256(1), address(aliceIdentity), signature, data, string(""))
            )
        });
        batch[1] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "removeClaim(bytes32)", keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic))
            )
        });

        bytes32 batchMode = bytes32(uint256(0x01) << 248); // CALLTYPE_BATCH in mode byte
        testExec.callExecuteFromExecutor(address(aliceIdentity), batchMode, abi.encode(batch));
    }

    /// @notice BATCH path: any non-claim selector in a CLAIM_SIGNER's batch poisons the whole batch.
    function test_executeFromExecutor_claimSignerExecutor_batchMixedSelectors_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "addClaim(uint256,uint256,address,bytes,bytes,string)",
                uint256(100),
                uint256(1),
                address(aliceIdentity),
                bytes(""),
                bytes("payload"),
                string("")
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
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        // SINGLE layout: target(20) + value(32) — exactly 52 bytes, no inner data at all.
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0));

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice Malformed SINGLE payload (length < 52) is rejected at the layout guard.
    function test_executeFromExecutor_singleCalldata_lengthBelow52_reverts() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
        vm.stopPrank();

        // Truncated payload — only the 20-byte target, no value field.
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity));

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    // -----------------------------------------------------------------------
    // Rule-consolidation tests — `KeyApprovalModule` is the single source of
    // truth for the authorization table. `SmartAccount._isKeyAuthorizedToCallTarget`
    // delegates to the module via STATICCALL and falls back to the conservative
    // pre-consolidation rule (self → MANAGEMENT, else → ACTION) when no policy
    // module is installed or its call reverts.
    // -----------------------------------------------------------------------

    /// @notice The module's external `canAutoApprove` rejects queries for any account
    ///         other than `msg.sender`. Prevents one identity from reading another's rule.
    function test_canAutoApprove_externalAccount_mismatch_reverts() public {
        KeyApprovalModule kam = onchainidSetup.keyApprovalModule;
        // Query under an arbitrary EOA — `msg.sender` is that EOA, not aliceIdentity.
        vm.expectRevert(Errors.UnauthorizedPolicyQuery.selector);
        kam.canAutoApprove(address(aliceIdentity), keccak256(abi.encodePacked(alice)), address(0), "");
    }

    /// @notice Module-installed path: `_isKeyAuthorizedToCallTarget` delegates to the queue
    ///         module, so a CLAIM_SIGNER-only executor can dispatch `addClaim` on self.
    ///         Regression for the existing claim-signer flow under the consolidated design.
    function test_executeFromExecutor_path_consultsKeyApprovalModule() public {
        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        // Self-issued claims now require a valid signature from one of the identity's CLAIM_SIGNER keys.
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: bytes("payload") });
        bytes memory signature =
            ClaimSignerHelper.signClaim(carolPk, carol, address(aliceIdentity), address(aliceIdentity), 201, data);

        bytes memory addClaimData = abi.encodeCall(
            IERC735.addClaim, (uint256(201), uint256(1), address(aliceIdentity), signature, data, string(""))
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice No-policy strict fallback: with `KeyApprovalModule` uninstalled, an ACTION
    ///         executor can still dispatch external calls — the pre-PR rule applies.
    function test_executeFromExecutor_path_noPolicyInstalled_strictFallback_actionExternal() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        // Uninstall the fallback handler for `execute` so policy discovery returns address(0).
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.ACTION, KeyTypes.ECDSA);
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "ACTION executor + no policy must still hit external target");
    }

    /// @notice No-policy strict fallback: a CLAIM_SIGNER-only executor CANNOT dispatch
    ///         `addClaim` on self without the policy module — the conservative rule applies.
    function test_executeFromExecutor_path_noPolicyInstalled_strictFallback_claimSignerSelfFails() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        TestExecutor testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        bytes memory addClaimData = abi.encodeWithSignature(
            "addClaim(uint256,uint256,address,bytes,bytes,string)",
            uint256(202),
            uint256(1),
            address(aliceIdentity),
            bytes(""),
            bytes("payload"),
            string("")
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice If the installed policy reverts in `canAutoApprove`, the account falls through
    ///         to the conservative rule. A CLAIM_SIGNER-only executor calling `addClaim` self
    ///         must be rejected (the strict fallback does not honor the claim selectors).
    function test_executeFromExecutor_path_brokenPolicy_fallsBackToStrictRule() public {
        // Replace the real fallback handler with a deliberately-reverting one.
        address kam = address(onchainidSetup.keyApprovalModule);
        vm.startPrank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        BrokenPolicy broken = new BrokenPolicy();
        aliceIdentity.installModule(
            MODULE_TYPE_FALLBACK, address(broken), abi.encodePacked(IKeyExecutor.execute.selector)
        );

        TestExecutor testExec = new TestExecutor();
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        vm.stopPrank();

        bytes memory addClaimData = abi.encodeWithSignature(
            "addClaim(uint256,uint256,address,bytes,bytes,string)",
            uint256(203),
            uint256(1),
            address(aliceIdentity),
            bytes(""),
            bytes("payload"),
            string("")
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice With a broken policy installed, the strict fallback still authorizes ACTION
    ///         on external targets — proving the try/catch never leaves the gate stuck-true.
    function test_executeFromExecutor_path_brokenPolicy_strictRuleStillAllowsAction() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        vm.startPrank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        BrokenPolicy broken = new BrokenPolicy();
        aliceIdentity.installModule(
            MODULE_TYPE_FALLBACK, address(broken), abi.encodePacked(IKeyExecutor.execute.selector)
        );

        TestExecutor testExec = new TestExecutor();
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), KeyPurposes.ACTION, KeyTypes.ECDSA);
        vm.stopPrank();

        Counter counter = new Counter();
        bytes memory call = abi.encodeCall(Counter.increment, ());
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), call);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "broken policy must not lock out ACTION on external targets");
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
    function test_validateUserOp_actionKey_selfTarget_fails() public {
        bytes memory innerCall = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildAndSignUserOp(address(aliceIdentity), innerCall);

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "ACTION must not be able to self-target addKey");
    }

    /// @notice A signer not registered as a key on the identity fails at the validator's
    ///         purpose check (signature is valid, but the signer has no ACTION).
    function test_validateUserOp_unregisteredSigner_fails() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger");
        Counter counter = new Counter();
        bytes memory innerCall = abi.encodeCall(Counter.increment, ());

        // Build the UserOp shell, then sign with the stranger instead of david.
        bytes memory executionCalldata = abi.encodePacked(address(counter), uint256(0), innerCall);
        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
        PackedUserOperation memory userOp = PackedUserOperation({
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
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(strangerPk, userOpHash);
        userOp.signature = abi.encode(abi.encodePacked(stranger), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        uint256 result = IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "unregistered signer must fail at ACTION check");
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

/// @notice ERC-7579 FALLBACK module whose `canAutoApprove` always reverts. Used to verify
///         that `SmartAccount._isKeyAuthorizedToCallTarget` recovers via try/catch and applies
///         the conservative pre-consolidation rule instead of bricking the account.
contract BrokenPolicy is IERC7579Module {

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    function onInstall(bytes calldata) external pure { }
    function onUninstall(bytes calldata) external pure { }

    function canAutoApprove(address, bytes32, address, bytes calldata) external pure returns (bool) {
        revert("nope");
    }

}
