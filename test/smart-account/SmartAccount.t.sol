// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
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

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice Coverage for the SmartAccount execution surface and ERC-734 purpose invariants.
contract SmartAccountTest is OnchainIDSetup {

    // ---- UserOp-flow helpers (used by the validateUserOp coverage tests at the bottom) ----

    // ERC-7579 mode words (top byte of `bytes32(mode)`): CALLTYPE in bits 248..255.
    bytes32 internal constant _SINGLE_MODE = bytes32(0);
    bytes32 internal constant _BATCH_MODE = bytes32(uint256(0x01) << 248);
    bytes32 internal constant _STATIC_MODE = bytes32(uint256(0xFE) << 248);

    address internal _validator;
    address internal _entryPoint;

    function setUp() public override {
        super.setUp();
        _validator = address(onchainidSetup.signatureValidator);
        _entryPoint = address(aliceIdentity.entryPoint());
    }

    function _nonceFor(address validatorAddr) internal pure returns (uint256) {
        return uint256(uint160(validatorAddr)) << 96;
    }

    function _signUserOp(uint256 pk, address signer, bytes32 opHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, opHash);
        return abi.encode(abi.encodePacked(signer), abi.encodePacked(r, s, v));
    }

    function _baseOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op.sender = address(aliceIdentity);
        op.nonce = _nonceFor(_validator);
        op.callData = callData;
    }

    /// @dev Recurring setup for ~20 executor tests: deploy a fresh `TestExecutor`, install it
    ///      on aliceIdentity, and grant the given purpose to the executor's address-as-key.
    ///      All three steps happen under `vm.startPrank(alice)` (alice is MANAGEMENT on
    ///      aliceIdentity). Returns the executor so the test can drive `callExecuteFromExecutor`.
    function _installExecutorWithPurpose(uint256 purpose) internal returns (TestExecutor testExec) {
        testExec = new TestExecutor();
        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(testExec), "");
        aliceIdentity.addKey(keccak256(abi.encodePacked(address(testExec))), purpose, KeyTypes.ECDSA);
        vm.stopPrank();
    }

    /// @dev Builds the ABI-encoded `addClaim(uint256,uint256,address,bytes,bytes,string)` call
    ///      for a self-issued claim on aliceIdentity. Used by the executor/UserOp tests that
    ///      target the addClaim selector. Always uses scheme=1 (ECDSA), empty signature
    ///      (self-issued claims skip `_isClaimValid`), and `bytes("payload")` as data.
    function _addClaimOnSelf(uint256 topic) internal view returns (bytes memory) {
        return abi.encodeWithSignature(
            "addClaim(uint256,uint256,address,bytes,bytes,string)",
            topic,
            uint256(1),
            address(aliceIdentity),
            bytes(""),
            bytes("payload"),
            string("")
        );
    }

    /// @dev Deploys a fresh Counter and returns it with the SINGLE-mode executionCalldata that
    ///      calls `Counter.increment()` on it (target(20) || value(32) || encodedCall).
    function _counterCall() internal returns (Counter counter, bytes memory executionCalldata) {
        counter = new Counter();
        executionCalldata = abi.encodePacked(address(counter), uint256(0), abi.encodeCall(Counter.increment, ()));
    }

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

        (, bytes memory executionCalldata) = _counterCall();

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor granted ACTION purpose can dispatch external calls.
    function test_executeFromExecutor_actionExecutor_canCallExternal() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.ACTION);

        (Counter counter, bytes memory executionCalldata) = _counterCall();

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "ACTION executor should dispatch external");
    }

    /// @notice An executor granted ACTION purpose CANNOT dispatch a self-targeted call.
    ///         Self-modification requires the executor's key to hold MANAGEMENT.
    function test_executeFromExecutor_actionExecutor_cannotCallSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.ACTION);

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
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.MANAGEMENT);

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
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        // Self-issued claim — no external isClaimValid round trip.
        bytes memory addClaimData = _addClaimOnSelf(42);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);

        // Post-condition: the claim is actually present in identity storage and the topic
        // index reflects it. A silent no-op in the executor dispatch would fail these reads.
        bytes32 claimId = keccak256(abi.encode(address(aliceIdentity), uint256(42)));
        (uint256 topic, uint256 scheme, address issuer, bytes memory sig, bytes memory data, string memory uri) =
            IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, 42, "claim topic should be 42");
        assertEq(scheme, 1, "claim scheme should be 1");
        assertEq(issuer, address(aliceIdentity), "claim issuer should be alice");
        assertEq(sig.length, 0, "claim sig should be empty");
        assertEq(string(data), "payload", "claim data should be payload");
        assertEq(uri, "", "claim uri should be empty");
        bytes32[] memory ids = IERC735(address(aliceIdentity)).getClaimIdsByTopic(42);
        assertEq(ids.length, 1, "topic 42 index should have exactly one claim");
        assertEq(ids[0], claimId, "topic 42 index should point at the new claim");
    }

    /// @notice An executor whose key holds CLAIM_SIGNER can dispatch `removeClaim` on self.
    function test_executeFromExecutor_claimSignerExecutor_canRemoveClaimOnSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        // aliceClaim666 already exists in the fixture. Use its claimId.
        bytes32 claimId = keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic));

        // Pre-condition: confirm the claim and topic index are non-empty before removal,
        // so the post-condition can attribute any zeroing to the executor call.
        (uint256 topicBefore,,,,,) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topicBefore, aliceClaim666.topic, "fixture claim should exist before removal");
        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(aliceClaim666.topic).length, 1);

        bytes memory removeClaimData = abi.encodeWithSignature("removeClaim(bytes32)", claimId);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), removeClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);

        // Post-condition: the claim is gone from both the by-id mapping and the topic index.
        (uint256 topicAfter,, address issuerAfter,,,) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topicAfter, 0, "claim slot should be cleared after removal");
        assertEq(issuerAfter, address(0), "claim issuer should be cleared after removal");
        assertEq(
            IERC735(address(aliceIdentity)).getClaimIdsByTopic(aliceClaim666.topic).length,
            0,
            "topic index should be empty after removal"
        );
    }

    /// @notice A CLAIM_SIGNER executor MUST NOT escalate to other self-selectors like `addKey`.
    function test_executeFromExecutor_claimSignerExecutor_cannotAddKeyOnSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        bytes32 evilKey = keccak256("evil-mgmt-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addKeyData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice An executor whose key holds CLAIM_ADDER can dispatch `addClaim` on self.
    function test_executeFromExecutor_claimAdderExecutor_canAddClaimOnSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_ADDER);

        bytes memory addClaimData = _addClaimOnSelf(43);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);

        // Post-condition: claim landed in storage. Mirrors the CLAIM_SIGNER case for symmetry.
        bytes32 claimId = keccak256(abi.encode(address(aliceIdentity), uint256(43)));
        (uint256 topic,, address issuer,, bytes memory data,) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, 43, "claim topic should be 43");
        assertEq(issuer, address(aliceIdentity), "claim issuer should be alice");
        assertEq(string(data), "payload", "claim data should be payload");
        bytes32[] memory ids = IERC735(address(aliceIdentity)).getClaimIdsByTopic(43);
        assertEq(ids.length, 1, "topic 43 index should have exactly one claim");
        assertEq(ids[0], claimId, "topic 43 index should point at the new claim");
    }

    /// @notice A CLAIM_ADDER executor MUST NOT be able to dispatch `removeClaim` on self.
    function test_executeFromExecutor_claimAdderExecutor_cannotRemoveClaimOnSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_ADDER);

        bytes32 claimId = keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic));
        bytes memory removeClaimData = abi.encodeWithSignature("removeClaim(bytes32)", claimId);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), removeClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice A CLAIM_ADDER-only key must not be able to dispatch an arbitrary external call.
    ///         The executor-as-key path mirrors what `_validateUserOp` would do for a UserOp
    ///         signer with the same purpose.
    function test_executeFromExecutor_claimAdderExecutor_cannotCallExternal() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_ADDER);

        (, bytes memory executionCalldata) = _counterCall();

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice BATCH path: a CLAIM_SIGNER executor can dispatch `[addClaim, removeClaim]` on self.
    function test_executeFromExecutor_claimSignerExecutor_batchAddRemoveOnSelf() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({ target: address(aliceIdentity), value: 0, callData: _addClaimOnSelf(99) });
        batch[1] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "removeClaim(bytes32)", keccak256(abi.encode(address(claimIssuer), aliceClaim666.topic))
            )
        });

        testExec.callExecuteFromExecutor(address(aliceIdentity), _BATCH_MODE, abi.encode(batch));
    }

    /// @notice BATCH path: any non-claim selector in a CLAIM_SIGNER's batch poisons the whole batch.
    function test_executeFromExecutor_claimSignerExecutor_batchMixedSelectors_reverts() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({ target: address(aliceIdentity), value: 0, callData: _addClaimOnSelf(100) });
        batch[1] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
            )
        });

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), _BATCH_MODE, abi.encode(batch));
    }

    /// @notice Short calldata guard: a self-targeted SINGLE payload with no selector is rejected.
    function test_executeFromExecutor_selfTarget_calldataTooShort_reverts() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        // SINGLE layout: target(20) + value(32) — exactly 52 bytes, no inner data at all.
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0));

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice Malformed SINGLE payload (length < 52) is rejected at the layout guard.
    function test_executeFromExecutor_singleCalldata_lengthBelow52_reverts() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.MANAGEMENT);

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
    function test_executeFromExecutor_consultsKeyApprovalModule() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        bytes memory addClaimData = _addClaimOnSelf(201);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice No-policy strict fallback: with `KeyApprovalModule` uninstalled, an ACTION
    ///         executor can still dispatch external calls — the pre-PR rule applies.
    function test_executeFromExecutor_noPolicyInstalled_strictFallback_actionExternal() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        // Uninstall the fallback handler for `execute` so policy discovery returns address(0).
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.ACTION);

        (Counter counter, bytes memory executionCalldata) = _counterCall();

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "ACTION executor + no policy must still hit external target");
    }

    /// @notice No-policy strict fallback: a CLAIM_SIGNER-only executor CANNOT dispatch
    ///         `addClaim` on self without the policy module — the conservative rule applies.
    function test_executeFromExecutor_noPolicyInstalled_strictFallback_claimSignerSelfFails() public {
        address kam = address(onchainidSetup.keyApprovalModule);
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, kam, abi.encodePacked(IKeyExecutor.execute.selector));

        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.CLAIM_SIGNER);

        bytes memory addClaimData = _addClaimOnSelf(202);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice If the installed policy reverts in `canAutoApprove`, the account falls through
    ///         to the conservative rule. A CLAIM_SIGNER-only executor calling `addClaim` self
    ///         must be rejected (the strict fallback does not honor the claim selectors).
    function test_executeFromExecutor_brokenPolicy_fallsBackToStrictRule() public {
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

        bytes memory addClaimData = _addClaimOnSelf(203);
        bytes memory executionCalldata = abi.encodePacked(address(aliceIdentity), uint256(0), addClaimData);

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
    }

    /// @notice With a broken policy installed, the strict fallback still authorizes ACTION
    ///         on external targets — proving the try/catch never leaves the gate stuck-true.
    function test_executeFromExecutor_brokenPolicy_strictRuleStillAllowsAction() public {
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

        (Counter counter, bytes memory executionCalldata) = _counterCall();

        testExec.callExecuteFromExecutor(address(aliceIdentity), bytes32(0), executionCalldata);
        assertEq(counter.count(), 1, "broken policy must not lock out ACTION on external targets");
    }

    // -----------------------------------------------------------------------
    // supportsExecutionMode — ERC-7579 §"Account configurations"
    //   SINGLE and BATCH are the only modes `_isAuthorizedForExecution` accepts.
    //   These tests pin that the account advertises both.
    // -----------------------------------------------------------------------

    function test_supportsExecutionMode_single_advertised() public view {
        assertTrue(aliceIdentity.supportsExecutionMode(_SINGLE_MODE), "SINGLE must be advertised");
    }

    function test_supportsExecutionMode_batch_advertised() public view {
        assertTrue(aliceIdentity.supportsExecutionMode(_BATCH_MODE), "BATCH must be advertised");
    }

    // -----------------------------------------------------------------------
    // callData length-guard arm in _isAuthorizedForUserOpCallData
    // -----------------------------------------------------------------------

    /// @notice Empty callData triggers the `callData.length < 4` short-circuit in
    ///         `_isAuthorizedForUserOpCallData`. Must surface as SIG_VALIDATION_FAILED, not revert.
    function test_validateUserOp_emptyCallData_failsViaLengthGuard() public {
        PackedUserOperation memory op = _baseOp("");
        bytes32 opHash = keccak256("empty-cd");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "empty callData must yield SIG_VALIDATION_FAILED");
    }

    /// @notice callData with only 3 bytes can't carry a selector — must still short-circuit.
    function test_validateUserOp_threeByteCallData_failsViaLengthGuard() public {
        PackedUserOperation memory op = _baseOp(hex"010203");
        bytes32 opHash = keccak256("three-cd");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "3-byte callData must yield SIG_VALIDATION_FAILED");
    }

    // -----------------------------------------------------------------------
    // CALLTYPE_STATIC (0xFE) — rejected by _isAuthorizedForExecution
    // -----------------------------------------------------------------------

    /// @notice `_isAuthorizedForExecution` falls through to `return false` for any call type
    ///         other than SINGLE / BATCH. STATIC (0xFE) is the other documented-but-unsupported
    ///         mode (alongside DELEGATECALL). UserOp path → SIG_VALIDATION_FAILED.
    function test_validateUserOp_staticCallTypeMode_fails() public {
        (Counter counter, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (_STATIC_MODE, inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("static");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "STATIC call type must be rejected");
        assertEq(counter.count(), 0, "execution must not have run");
    }

    /// @notice Same as above but via `executeFromExecutor` — exercises the executor-side
    ///         entry into `_isAuthorizedForExecution`. The catch-all `return false`
    ///         then surfaces as `ExecutorPurposeNotAuthorized`.
    function test_executeFromExecutor_staticCallTypeMode_reverts() public {
        TestExecutor testExec = _installExecutorWithPurpose(KeyPurposes.ACTION);

        (, bytes memory executionCalldata) = _counterCall();

        vm.expectRevert(Errors.ExecutorPurposeNotAuthorized.selector);
        testExec.callExecuteFromExecutor(address(aliceIdentity), _STATIC_MODE, executionCalldata);
    }

    // -----------------------------------------------------------------------
    // accountId / version — pin the ERC-7579 vendor / version strings
    // -----------------------------------------------------------------------

    /// @notice ERC-7579 `accountId()` must return the expected vendor / version label. Any
    ///         drift here is a spec change worth flagging in CI.
    function test_accountId_returnsExpectedLabel() public view {
        assertEq(aliceIdentity.accountId(), "trex.onchainid.identity.v3.0.0");
    }

    function test_version_returnsExpectedString() public view {
        assertEq(aliceIdentity.version(), "3.0.0");
    }

    // -----------------------------------------------------------------------
    // Executor-installed gate in `executeFromExecutor`
    // -----------------------------------------------------------------------

    /// @notice Pins the executor-installed gate in `executeFromExecutor`. Any caller
    ///         that is not a registered `MODULE_TYPE_EXECUTOR` MUST revert with
    ///         `ExecutorPurposeNotAuthorized` before `_isAuthorizedForExecution` is reached.
    function test_executeFromExecutor_nonInstalledCaller_reverts() public {
        // david is a registered ACTION key on aliceIdentity but is NOT an installed
        // MODULE_TYPE_EXECUTOR module. The purpose check passes (ACTION may call an external
        // target), so the revert comes from the executor-module guard in super.executeFromExecutor.
        bytes memory executionCalldata = abi.encodePacked(makeAddr("target"), uint256(0), hex"deadbeef");
        vm.prank(david);
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Utils.ERC7579UninstalledModule.selector, MODULE_TYPE_EXECUTOR, david)
        );
        aliceIdentity.executeFromExecutor(bytes32(0), executionCalldata);
    }

    // -----------------------------------------------------------------------
    // Full UserOp validation + execution flow.
    // -----------------------------------------------------------------------

    /// @notice End-to-end happy path: validate then execute.
    function test_userOpE2E_happyPath_validateAndExecute_incrementsCounter() public {
        (Counter c, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("happy");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.startPrank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_SUCCESS, "validation should pass");
        (bool ok,) = address(aliceIdentity).call(op.callData);
        assertTrue(ok, "execution should succeed");
        vm.stopPrank();

        assertEq(c.count(), 1);
    }

    /// @notice EntryPoint sees invalid signature → does not execute.
    function test_userOpE2E_invalidSignature_validateReturnsFailureCode() public {
        (Counter c, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("bad");
        // Sign with carol (CLAIM_SIGNER) — fails the per-target ACTION check on an external target.
        op.signature = _signUserOp(carolPk, carol, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "must return SIG_VALIDATION_FAILED");
        assertEq(c.count(), 0, "execution must not have run");
    }

    /// @notice BATCH path with mixed-authority calls → SIG_VALIDATION_FAILED.
    function test_userOpE2E_batch_mixedAuthority_fails() public {
        Counter c = new Counter();
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({ target: address(c), value: 0, callData: abi.encodeCall(Counter.increment, ()) });
        batch[1] = Execution({
            target: address(aliceIdentity),
            value: 0,
            callData: abi.encodeWithSignature(
                "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
            )
        });
        bytes memory callData =
            abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (_BATCH_MODE, abi.encode(batch)));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("mixed");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "mixed-authority batch must be rejected");
    }

    /// @notice CLAIM_SIGNER UserOp on addClaim(self) → accepted.
    /// @notice After the upstream "harden AA path" change (commit 3ffabc6), the
    ///         `ERC7579Signature` validator hardcodes `KeyPurposes.ACTION` for every UserOp
    ///         it accepts. A CLAIM_SIGNER-only key can still execute self-targeted addClaim
    ///         via the synchronous `execute()` path (queue module auto-approves the claim
    ///         selectors), but cannot route the same call through the 4337 entry point.
    ///         This test pins the new gate: CLAIM_SIGNER ⇒ SIG_VALIDATION_FAILED.
    function test_userOpE2E_claimSigner_addClaimSelf_failsUnderHardenedAA() public {
        bytes memory inner = abi.encodePacked(address(aliceIdentity), uint256(0), _addClaimOnSelf(777));
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("claimSelf");
        op.signature = _signUserOp(carolPk, carol, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(
            vd, ERC4337Utils.SIG_VALIDATION_FAILED, "CLAIM_SIGNER must NOT validate UserOps under the hardened AA path"
        );
    }

    /// @notice fuzz: arbitrary executionCalldata bytes → no revert from the layout guard.
    function testFuzz_execute_arbitraryExecutionCalldata_noRevert(bytes calldata raw) public {
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), raw));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("fuzz-exec");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        // Just assert no revert. Result may be 0 or 1 depending on the random bytes.
        aliceIdentity.validateUserOp(op, opHash, 0);
    }

    /// @notice Malformed BATCH executionCalldata: `_isAuthorizedForExecutionExternal` reverts
    ///         inside ERC7579Utils.decodeBatch; the outer try/catch returns false and
    ///         validateUserOp surfaces SIG_VALIDATION_FAILED.
    function test_userOpE2E_batch_malformedCalldata_revertsOnDecode() public {
        // BATCH mode but executionCalldata is just garbage bytes. The per-target rule decodes
        // the batch during validateUserOp, so malformed bytes revert with ERC7579DecodingError.
        bytes memory executionCalldata = hex"deadbeef";
        bytes memory callData =
            abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (_BATCH_MODE, executionCalldata));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("badbatch");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        vm.expectRevert(ERC7579Utils.ERC7579DecodingError.selector);
        aliceIdentity.validateUserOp(op, opHash, 0);
    }

    /// @notice fuzz: only known mode bytes accepted. Asserts the validator returns
    ///         SIG_VALIDATION_FAILED for any mode word whose top byte is neither 0x00 (SINGLE)
    ///         nor 0x01 (BATCH).
    function testFuzz_modeWord_onlySingleAndBatchAccepted(uint8 callTypeByte) public {
        vm.assume(callTypeByte != 0 && callTypeByte != 1);
        (, bytes memory inner) = _counterCall();
        bytes32 mode = bytes32(uint256(callTypeByte) << 248);
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (mode, inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("mode");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 vd = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(vd, ERC4337Utils.SIG_VALIDATION_FAILED, "non-SINGLE/non-BATCH mode must fail");
    }

    // -----------------------------------------------------------------------
    // Per-gate validateUserOp coverage.
    // -----------------------------------------------------------------------

    /// @notice ACTION key UserOp on external target is accepted.
    function test_validateUserOp_actionKey_externalCall_passes() public {
        (, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("opHash");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS, "ACTION key + external target must validate");
    }

    /// @notice CLAIM_SIGNER-only UserOp on `addKey(self)` is rejected.
    function test_validateUserOp_claimSignerSelfAddKey_fails() public {
        bytes memory selfCall =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", bytes32(0), KeyPurposes.ACTION, KeyTypes.ECDSA);
        bytes memory inner = abi.encodePacked(address(aliceIdentity), uint256(0), selfCall);
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("selfAddKey");
        op.signature = _signUserOp(carolPk, carol, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "SIG_VALIDATION_FAILED expected");
    }

    /// @notice ACTION-only UserOp on a self-targeted call is rejected.
    function test_validateUserOp_actionKey_selfCall_fails() public {
        bytes memory selfCall =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", bytes32(0), KeyPurposes.ACTION, KeyTypes.ECDSA);
        bytes memory inner = abi.encodePacked(address(aliceIdentity), uint256(0), selfCall);
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("actionSelf");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice Unknown validator named in nonce → SIG_VALIDATION_FAILED.
    function test_validateUserOp_unknownValidator_fails() public {
        (, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        op.nonce = _nonceFor(address(0xBEEF));
        bytes32 opHash = keccak256("unkv");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice Unregistered signer → SIG_VALIDATION_FAILED.
    function test_validateUserOp_unregisteredSigner_fails() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger-userop");
        (, bytes memory inner) = _counterCall();
        bytes memory callData = abi.encodeCall(Identity(payable(address(aliceIdentity))).execute, (bytes32(0), inner));

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("stranger");
        op.signature = _signUserOp(strangerPk, stranger, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice callData with wrong selector (not `execute`) → SIG_VALIDATION_FAILED.
    function test_validateUserOp_wrongSelector_fails() public {
        bytes memory callData = abi.encodeWithSignature("foo()");

        PackedUserOperation memory op = _baseOp(callData);
        bytes32 opHash = keccak256("wsel");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        uint256 result = aliceIdentity.validateUserOp(op, opHash, 0);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice Pins `_isAuthorizedForExecutionExternal`'s self-only re-entry guard. External
    ///         callers must not be able to reach the helper directly.
    function test_isAuthorizedForExecutionExternal_externalCaller_reverts() public {
        bytes memory call = abi.encodeWithSignature(
            "_isAuthorizedForExecutionExternal(bytes32,bytes,bytes32)",
            bytes32(0),
            bytes(""),
            keccak256(abi.encodePacked(david))
        );
        vm.prank(david);
        (bool ok,) = address(aliceIdentity).call(call);
        assertFalse(ok, "external caller must not reach _isAuthorizedForExecutionExternal");
    }

    /// @notice fuzz: random calldata → never reverts (returns 1 or the validator's result).
    function testFuzz_validateUserOp_neverReverts(bytes calldata randomData) public {
        vm.assume(randomData.length >= 4); // we want msg.data slicing to be safe
        PackedUserOperation memory op = _baseOp(randomData);
        bytes32 opHash = keccak256("fuzz");
        op.signature = _signUserOp(davidPk, david, opHash);

        vm.prank(_entryPoint);
        // We just assert no revert.
        aliceIdentity.validateUserOp(op, opHash, 0);
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
