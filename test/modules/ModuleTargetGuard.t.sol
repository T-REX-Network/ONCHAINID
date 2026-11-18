// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { RecoveryModule } from "contracts/modules/executors/RecoveryModule.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockStockECDSAValidator } from "../mocks/MockStockECDSAValidator.sol";

/// @notice H-03 and H-04: a key below MANAGEMENT must not be able to make the account call an
///         ERC-7579 module. Modules keep their settings per account, keyed on `msg.sender`, so
///         such a call reads to the module as the account configuring itself.
///
///         In the fixture, `alice` holds MANAGEMENT on `aliceIdentity` and `david` holds ACTION.
///         Each attack is tried through both paths an ACTION key has:
///           * a user op validated by the enshrined ERC734Validator, then run by the EntryPoint;
///           * a request to the KeyApprovalModule, which auto-runs it for an ACTION key.
contract ModuleTargetGuardTest is OnchainIDSetup {

    /// @dev Same canonical EntryPoint the account trusts; see PrivilegedReentryGuard.t.sol.
    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    address internal attacker;
    uint256 internal attackerPk;

    function setUp() public override {
        super.setUp();
        (attacker, attackerPk) = makeAddrAndKey("attacker");
    }

    // ---- H-03: a second installed validator -----------------------------------------------

    /// @notice MANAGEMENT installs a stock validator with an honest signer. An ACTION key then
    ///         tries to swap that signer for the attacker. The user op passes the ERC734Validator
    ///         (the stock validator is an external target there), but the account refuses to
    ///         dispatch it, so the honest signer stays.
    function test_actionKey_cannotReconfigureSecondValidator_viaUserOp() public {
        MockStockECDSAValidator second = _installStockValidator(alice);
        bytes memory callData =
            _executeSingle(address(second), abi.encodeCall(IERC7579Module.onInstall, (abi.encodePacked(attacker))));

        // Validation alone does not stop it: david holds ACTION and the target looks external.
        assertEq(_validateAsDavid(callData), ERC4337Utils.SIG_VALIDATION_SUCCESS, "ERC734Validator accepts the op");

        // Execution does.
        vm.prank(ENTRY_POINT);
        (bool ok, bytes memory ret) = address(aliceIdentity).call(callData);
        assertFalse(ok, "dispatch into the second validator must be blocked");
        assertEq(ret, abi.encodeWithSelector(Errors.ModuleTargetBlocked.selector, address(second)));

        assertEq(second.signer(address(aliceIdentity)), alice, "the honest signer must stay");
    }

    /// @notice Same attack through the KeyApprovalModule. The request auto-runs for an ACTION
    ///         key, the account refuses the dispatch, and the request is recorded as failed.
    function test_actionKey_cannotReconfigureSecondValidator_viaKeyApprovalModule() public {
        MockStockECDSAValidator second = _installStockValidator(alice);

        bool ran =
            _queueAsDavid(address(second), abi.encodeCall(IERC7579Module.onInstall, (abi.encodePacked(attacker))));

        assertFalse(ran, "the dispatch must fail");
        assertEq(second.signer(address(aliceIdentity)), alice, "the honest signer must stay");
    }

    // ---- H-04: a module that is not installed yet -----------------------------------------

    /// @notice An ACTION key tries to set up a RecoveryModule that alice has not installed yet,
    ///         with an attacker guardian. The module is not installed, but it reports its module
    ///         type, so the account still refuses the dispatch.
    function test_actionKey_cannotPlantRecoveryBeforeInstall_viaUserOp() public {
        RecoveryModule recovery = new RecoveryModule();
        bytes memory callData =
            _executeSingle(address(recovery), abi.encodeCall(IERC7579Module.onInstall, (_attackerRecoveryConfig())));

        vm.prank(ENTRY_POINT);
        (bool ok, bytes memory ret) = address(aliceIdentity).call(callData);
        assertFalse(ok, "dispatch into an uninstalled module must be blocked");
        assertEq(ret, abi.encodeWithSelector(Errors.ModuleTargetBlocked.selector, address(recovery)));

        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 0, "no guardian may be planted");
    }

    /// @notice Same attack through the KeyApprovalModule, which needs no EntryPoint at all.
    function test_actionKey_cannotPlantRecoveryBeforeInstall_viaKeyApprovalModule() public {
        RecoveryModule recovery = new RecoveryModule();

        bool ran =
            _queueAsDavid(address(recovery), abi.encodeCall(IERC7579Module.onInstall, (_attackerRecoveryConfig())));

        assertFalse(ran, "the dispatch must fail");
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 0, "no guardian may be planted");
    }

    // ---- what still works ------------------------------------------------------------------

    /// @notice MANAGEMENT can still configure a module, through the documented self-call: the
    ///         account calls `execute` on itself, and the inner call targets the module.
    function test_managementSelfCall_canStillConfigureAModule() public {
        MockStockECDSAValidator second = _installStockValidator(alice);
        address newSigner = makeAddr("newSigner");
        bytes memory inner =
            _executeSingle(address(second), abi.encodeCall(IERC7579Module.onInstall, (abi.encodePacked(newSigner))));

        vm.prank(alice);
        bool ran = _queue(address(aliceIdentity), inner);

        assertTrue(ran, "a MANAGEMENT self-call reaches the module");
        assertEq(second.signer(address(aliceIdentity)), newSigner);
    }

    /// @notice Ordinary targets are not mistaken for modules: an EOA, a contract without
    ///         `isModuleType`, and the identity precompile (0x04), which echoes its input.
    function test_actionKey_canStillCallNonModuleTargets() public {
        address[3] memory targets = [makeAddr("eoa"), address(new Plain()), address(0x04)];
        for (uint256 i = 0; i < targets.length; i++) {
            bool ran = _queueAsDavid(targets[i], abi.encodeCall(IERC7579Module.isModuleType, (MODULE_TYPE_VALIDATOR)));
            assertTrue(ran, "a non-module target must still be callable by an ACTION key");
        }
    }

    // ---- helpers ---------------------------------------------------------------------------

    function _installStockValidator(address honestSigner) internal returns (MockStockECDSAValidator validator) {
        validator = new MockStockECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(honestSigner));
    }

    /// @dev `execute(bytes32 mode, bytes executionCalldata)` with one call in SINGLE mode.
    function _executeSingle(address target, bytes memory innerCall) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC7579Execution.execute, (bytes32(0), abi.encodePacked(target, uint256(0), innerCall)));
    }

    /// @dev Queues `to.data` on the KeyApprovalModule as david and returns whether it ran.
    function _queueAsDavid(address to, bytes memory data) internal returns (bool ran) {
        vm.prank(david);
        return _queue(to, data);
    }

    /// @dev Queues `to.data` on the KeyApprovalModule (caller pranked by the test) and returns
    ///      whether the request ran successfully.
    function _queue(address to, bytes memory data) internal returns (bool ran) {
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(to, 0, data);
        return onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id).succeeded;
    }

    /// @dev Signs `callData` as a user op from david and runs ERC-4337 validation on it.
    function _validateAsDavid(bytes memory callData) internal returns (uint256) {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: uint256(uint160(address(onchainidSetup.signatureValidator))) << 96,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        userOp.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        return IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
    }

    /// @dev RecoveryModule install data with the attacker as the only guardian and no delay.
    ///      Format: [uint16(execLen), execArgs, uint16(msigLen), msigArgs].
    function _attackerRecoveryConfig() internal view returns (bytes memory) {
        bytes memory execArgs = abi.encodePacked(uint32(0), uint32(30 days));
        bytes[] memory guardians = new bytes[](1);
        guardians[0] = abi.encodePacked(attacker);
        uint64[] memory weights = new uint64[](1);
        weights[0] = 1;
        bytes memory msigArgs = abi.encode(guardians, uint64(1), weights);
        return abi.encodePacked(uint16(execArgs.length), execArgs, uint16(msigArgs.length), msigArgs);
    }

}

/// @dev A contract with no `isModuleType` and a fallback that accepts anything.
contract Plain {

    fallback() external { }

}
