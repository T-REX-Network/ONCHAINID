// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";

/// @notice ABI / lifecycle / accessor coverage for the two installed modules
///         (`ClaimsModule`, `KeyApprovalModule`). These selectors are reachable directly on
///         the module deployment — outside the identity's fallback dispatch — and are not
///         covered by the surface-level tests in `Claims.t.sol` / `Executions.t.sol`.
///
///         Two perspectives in one file:
///           1. Singleton perspective: tests against `onchainidSetup.{claims,keyApproval}Module`
///              (the same instances installed on `aliceIdentity`).
///           2. Fresh-instance perspective: tests against a brand-new module deployment, used
///              to pin the no-op lifecycle hooks and the default-state accessors without any
///              shared-fixture state interfering.
contract ModulesTest is OnchainIDSetup {

    ClaimsModule internal _claimsModule;
    KeyApprovalModule internal _keyApprovalModule;

    function setUp() public override {
        super.setUp();
        _claimsModule = onchainidSetup.claimsModule;
        _keyApprovalModule = onchainidSetup.keyApprovalModule;
    }

    // ============ ClaimsModule.isModuleType — all three arms ============

    function test_claimsModule_isModuleType_executor_true() public view {
        assertTrue(_claimsModule.isModuleType(MODULE_TYPE_EXECUTOR));
    }

    function test_claimsModule_isModuleType_fallback_true() public view {
        assertTrue(_claimsModule.isModuleType(MODULE_TYPE_FALLBACK));
    }

    function test_claimsModule_isModuleType_validator_false() public view {
        assertFalse(_claimsModule.isModuleType(MODULE_TYPE_VALIDATOR));
    }

    function test_claimsModule_isModuleType_unknownType_false() public view {
        assertFalse(_claimsModule.isModuleType(9999));
    }

    // ============ ClaimsModule.onInstall / onUninstall — no-op hooks must not revert ============

    /// @notice ERC-7579 `onInstall` / `onUninstall` are part of the module's required ABI even
    ///         when no per-account state is initialized. Existing tests only exercise them via
    ///         the identity's install path; this hits them directly on the singleton.
    function test_claimsModule_onInstall_doesNotRevert() public {
        _claimsModule.onInstall("");
        _claimsModule.onInstall(hex"deadbeef"); // arbitrary calldata accepted (ignored)
    }

    function test_claimsModule_onUninstall_doesNotRevert() public {
        _claimsModule.onUninstall("");
        _claimsModule.onUninstall(hex"cafe");
    }

    // ============ ClaimsModule.isClaimRevoked direct accessor ============

    /// @notice `isClaimRevoked` is a public view keyed on `msg.sender`. Called directly on the
    ///         module by an arbitrary EOA, `msg.sender` is the test contract — which has no
    ///         revoked claims — so the lookup must return false for any signature.
    function test_claimsModule_isClaimRevoked_callerWithNoState_returnsFalse() public view {
        bytes memory anySig = hex"010203";
        assertFalse(_claimsModule.isClaimRevoked(anySig));
    }

    // ============ KeyApprovalModule.isModuleType — all three arms ============

    function test_kam_isModuleType_executor_true() public view {
        assertTrue(_keyApprovalModule.isModuleType(MODULE_TYPE_EXECUTOR));
    }

    function test_kam_isModuleType_fallback_true() public view {
        assertTrue(_keyApprovalModule.isModuleType(MODULE_TYPE_FALLBACK));
    }

    function test_kam_isModuleType_validator_false() public view {
        assertFalse(_keyApprovalModule.isModuleType(MODULE_TYPE_VALIDATOR));
    }

    function test_kam_isModuleType_unknownType_false() public view {
        assertFalse(_keyApprovalModule.isModuleType(9999));
    }

    // ============ KeyApprovalModule.onInstall / onUninstall — no-op hooks ============

    function test_kam_onInstall_doesNotRevert() public {
        _keyApprovalModule.onInstall("");
    }

    function test_kam_onUninstall_doesNotRevert() public {
        _keyApprovalModule.onUninstall("");
    }

    // ============ KeyApprovalModule.getExecutionData edge cases ============

    /// @notice For an unknown executionId on a known account, the lookup returns a zero-filled
    ///         `Execution` struct (default-initialized mapping value). Tests the read-side
    ///         "no such request" branch.
    function test_kam_getExecutionData_unknownId_returnsEmpty() public view {
        KeyApprovalModule.Execution memory exec = _keyApprovalModule.getExecutionData(address(aliceIdentity), 99999);
        assertEq(exec.to, address(0));
        assertEq(exec.value, 0);
        assertEq(exec.data.length, 0);
        assertEq(exec.approved, false);
        assertEq(exec.executed, false);
    }

    /// @notice For an unknown account, the entire `_state[account]` map is default — every id
    ///         lookup returns empty.
    function test_kam_getExecutionData_unknownAccount_returnsEmpty() public {
        address unknownAccount = makeAddr("unknown");
        KeyApprovalModule.Execution memory exec = _keyApprovalModule.getExecutionData(unknownAccount, 0);
        assertEq(exec.to, address(0));
        assertEq(exec.value, 0);
    }

    // ============ Fresh-instance lifecycle / accessor checks ============

    /// @notice Direct invocation of the no-op lifecycle hooks on a fresh ClaimsModule. Foundry's
    ///         `--ir-minimum` source map sometimes loses install-time attribution for hooks
    ///         called via the identity; this fresh-instance path pins them explicitly.
    function test_claimsModule_lifecycleHooks_noop_freshInstance() public {
        ClaimsModule fresh = new ClaimsModule();
        fresh.onInstall("");
        fresh.onUninstall("");
        fresh.onInstall(hex"01");
        fresh.onUninstall(hex"02");
    }

    /// @notice Same as above for KeyApprovalModule.
    function test_keyApprovalModule_lifecycleHooks_noop_freshInstance() public {
        KeyApprovalModule fresh = new KeyApprovalModule();
        fresh.onInstall("");
        fresh.onUninstall("");
    }

    /// @notice `getCurrentNonce` on a fresh (never-used) KAM returns zero. Pins the
    ///         default-init semantics of the `_state` map.
    function test_keyApprovalModule_getCurrentNonce_freshInstance_zero() public {
        KeyApprovalModule fresh = new KeyApprovalModule();
        assertEq(fresh.getCurrentNonce(), 0);
    }

}
