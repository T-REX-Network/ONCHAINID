// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC7579DelayedExecutor } from "@openzeppelin/accounts/modules/executors/ERC7579DelayedExecutor.sol";
import {
    ERC7579SocialRecoveryExecutor
} from "@openzeppelin/accounts/modules/executors/ERC7579SocialRecoveryExecutor.sol";
import { IERC7579Execution, MODULE_TYPE_EXECUTOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { RecoveryModule } from "contracts/modules/executors/RecoveryModule.sol";

import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";

/// @notice A recovery can execute only in the installation that scheduled it.
///         Install and uninstall each move that account's generation. Another
///         account's schedules are a different counter.
contract RecoveryInstallGenerationTest is OnchainIDSetup {

    uint32 internal constant DELAY = 1 days;
    uint32 internal constant EXPIRATION = 30 days;
    uint64 internal constant THRESHOLD = 2;

    RecoveryModule internal recovery;
    bytes internal installData;

    address internal g1;
    uint256 internal g1Pk;
    address internal g2;
    uint256 internal g2Pk;
    address internal g3;
    uint256 internal g3Pk;
    address internal newOwner;

    function setUp() public override {
        super.setUp();

        recovery = new RecoveryModule();
        (g1, g1Pk) = makeAddrAndKey("guardian1");
        (g2, g2Pk) = makeAddrAndKey("guardian2");
        (g3, g3Pk) = makeAddrAndKey("guardian3");
        newOwner = makeAddr("recoveredOwner");

        installData = _installData(_guardians(), _weights(3), THRESHOLD);
        _install(aliceIdentity, alice);
    }

    /// @notice Uninstall retires the pending recovery. Reinstalling the same module
    ///         does not make that payload executable again.
    function test_oldRecoveryCannotExecuteAfterUninstallAndReinstall() public {
        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(19));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        // Captured while this installation is current. Execute hashes again later.
        bytes32 scheduledId = recovery.hashOperation(address(aliceIdentity), salt, mode, data);

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, address(recovery), "");

        assertFalse(aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(recovery), ""));
        assertFalse(_hasManagement(address(aliceIdentity), address(recovery)));
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 0);

        // The old id is still in the schedule map. The public inputs no longer reach it.
        vm.warp(block.timestamp + DELAY);
        assertEq(uint8(recovery.state(scheduledId)), uint8(ERC7579DelayedExecutor.OperationState.Ready));
        assertEq(_state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Unknown));
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);
        assertFalse(_hasManagement(address(aliceIdentity), newOwner));

        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(recovery), installData);

        assertEq(_state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Unknown));
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);
        assertFalse(_hasManagement(address(aliceIdentity), newOwner));
    }

    /// @notice A direct uninstall from the account clears guardians without going through
    ///         `uninstallModule`. The account-side install stays. The pending recovery does not.
    function test_directUninstallRetiresPendingRecovery() public {
        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(20));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        // The module has to see the identity as the caller, so the key queues a self-call.
        bytes memory moduleCall = abi.encodeWithSignature("onUninstall(bytes)", bytes(""));
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity))
            .execute(
                address(aliceIdentity),
                0,
                abi.encodeCall(
                    IERC7579Execution.execute, (bytes32(0), abi.encodePacked(address(recovery), uint256(0), moduleCall))
                )
            );

        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(recovery), ""));
        assertTrue(_hasManagement(address(aliceIdentity), address(recovery)));
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 0);
        assertEq(_state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Unknown));

        vm.warp(block.timestamp + DELAY);
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);
        assertFalse(_hasManagement(address(aliceIdentity), newOwner));

        // The guardian set was cleared with the uninstall, so a new quorum cannot schedule.
        bytes memory fresh = _addManagementKey(address(aliceIdentity), makeAddr("freshOwner"));
        bytes32 freshSalt = bytes32(uint256(21));
        bytes memory freshBundle = _quorum(_scheduleDigest(address(aliceIdentity), freshSalt, mode, fresh));
        vm.expectRevert(ERC7579SocialRecoveryExecutor.ERC7579SocialRecoveryExecutorInvalidSchedule.selector);
        recovery.startRecovery(address(aliceIdentity), freshSalt, mode, fresh, freshBundle);
    }

    /// @notice OZ account uninstall ignores a reverting module callback. Guardian
    ///         cleanup is unbounded, so a low-gas uninstall can otherwise succeed
    ///         while leaving the old operation generation and schedule live.
    function test_lowGasUninstallRetiresScheduleEvenWhenGuardianCleanupIsIncomplete() public {
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, address(recovery), "");

        bytes[] memory guardians = new bytes[](100);
        guardians[0] = abi.encodePacked(g1);
        guardians[1] = abi.encodePacked(g2);
        guardians[2] = abi.encodePacked(g3);
        for (uint256 i = 3; i < guardians.length; ++i) {
            guardians[i] = abi.encodePacked(address(uint160(i + 100)));
        }
        vm.prank(alice);
        aliceIdentity.installModule(
            MODULE_TYPE_EXECUTOR, address(recovery), _installData(guardians, _weights(guardians.length), THRESHOLD)
        );

        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(887));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        vm.prank(alice);
        (bool uninstalled,) = address(aliceIdentity).call{ gas: 100_000 }(
            abi.encodeWithSignature(
                "uninstallModule(uint256,address,bytes)", MODULE_TYPE_EXECUTOR, address(recovery), bytes("")
            )
        );
        assertTrue(uninstalled, "account uninstall completed despite low callback gas");
        assertFalse(aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(recovery), ""));
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 100, "cleanup could not finish");
        assertEq(_state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Unknown));

        vm.warp(block.timestamp + DELAY);
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);

        // The manager can finish module cleanup using an account self-call and
        // then reinstall. The old schedule remains retired in both generations.
        bytes memory cleanupCall = abi.encodeWithSignature("onUninstall(bytes)", bytes(""));
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity))
            .execute(
                address(aliceIdentity),
                0,
                abi.encodeCall(
                    IERC7579Execution.execute,
                    (bytes32(0), abi.encodePacked(address(recovery), uint256(0), cleanupCall))
                )
            );
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 0);

        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(recovery), installData);
        assertEq(_state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Unknown));
    }

    function test_cleanupHelperCannotBeCalledWithoutGenerationAdvance() public {
        vm.prank(address(aliceIdentity));
        vm.expectRevert(
            abi.encodeWithSelector(RecoveryModule.RecoveryCleanupNotInProgress.selector, address(aliceIdentity))
        );
        recovery.cleanupAfterUninstall("");
        assertEq(recovery.getGuardianCount(address(aliceIdentity)), 3);
    }

    /// @notice A recovery scheduled on the new installation executes after its own delay.
    ///         Reinstall does not grant the module key again; the account does.
    function test_recoveryScheduledAfterReinstallExecutesAfterItsDelay() public {
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, address(recovery), "");

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(recovery), installData);
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(recovery))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(recovery)),
            ""
        );
        vm.stopPrank();

        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(22));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        // Still inside this installation's delay.
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);

        vm.warp(block.timestamp + DELAY);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);

        assertTrue(_hasManagement(address(aliceIdentity), newOwner));
        assertEq(
            _state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Executed)
        );
    }

    /// @notice Alice uninstalling does not move Bob's generation. His recovery stays ready
    ///         and still executes.
    function test_anotherAccountsRecoveryStaysReady() public {
        _install(bobIdentity, bob);

        bytes memory data = _addManagementKey(address(bobIdentity), newOwner);
        bytes32 salt = bytes32(uint256(23));
        bytes32 mode = bytes32(0);
        _schedule(address(bobIdentity), salt, mode, data);
        bytes32 bobId = recovery.hashOperation(address(bobIdentity), salt, mode, data);

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_EXECUTOR, address(recovery), "");

        assertEq(recovery.hashOperation(address(bobIdentity), salt, mode, data), bobId);
        assertEq(_state(address(bobIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Scheduled));

        vm.warp(block.timestamp + DELAY);
        assertEq(_state(address(bobIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Ready));
        recovery.executeRecovery(address(bobIdentity), salt, mode, data);
        assertTrue(_hasManagement(address(bobIdentity), newOwner));
    }

    /// @notice Guardian cancellation still addresses the recovery, because the generation
    ///         has not moved since it was scheduled.
    function test_guardiansCanStillCancelTheCurrentRecovery() public {
        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(24));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        recovery.cancelRecovery(
            address(aliceIdentity), salt, mode, data, _quorum(_cancelDigest(address(aliceIdentity), salt, mode, data))
        );

        assertEq(
            _state(address(aliceIdentity), salt, mode, data), uint8(ERC7579DelayedExecutor.OperationState.Canceled)
        );
        vm.warp(block.timestamp + DELAY);
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);
        assertFalse(_hasManagement(address(aliceIdentity), newOwner));
    }

    /// @notice The account can still cancel its own pending recovery in the current installation.
    function test_accountCanStillCancelTheCurrentRecovery() public {
        bytes memory data = _addManagementKey(address(aliceIdentity), newOwner);
        bytes32 salt = bytes32(uint256(25));
        bytes32 mode = bytes32(0);
        _schedule(address(aliceIdentity), salt, mode, data);

        vm.prank(address(aliceIdentity));
        recovery.cancelRecovery(address(aliceIdentity), salt, mode, data);

        vm.warp(block.timestamp + DELAY);
        _expectExecuteReverts(address(aliceIdentity), salt, mode, data);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, data);
        assertFalse(_hasManagement(address(aliceIdentity), newOwner));
    }

    /// @dev Execute accepts only Ready. The id is the current generation's hash.
    function _expectExecuteReverts(address account, bytes32 salt, bytes32 mode, bytes memory data) internal {
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                recovery.hashOperation(account, salt, mode, data),
                recovery.state(account, salt, mode, data),
                bytes32(uint256(1) << uint8(ERC7579DelayedExecutor.OperationState.Ready))
            )
        );
    }

    function _install(Identity id, address manager) internal {
        vm.startPrank(manager);
        id.installModule(MODULE_TYPE_EXECUTOR, address(recovery), installData);
        id.addKeyWithData(
            keccak256(abi.encodePacked(address(recovery))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(recovery)),
            ""
        );
        vm.stopPrank();
    }

    function _schedule(address account, bytes32 salt, bytes32 mode, bytes memory data) internal {
        recovery.startRecovery(account, salt, mode, data, _quorum(_scheduleDigest(account, salt, mode, data)));
    }

    function _quorum(bytes32 digest) internal view returns (bytes memory) {
        bytes[] memory signers = new bytes[](2);
        bytes[] memory signatures = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        signatures[0] = _sign(g1Pk, digest);
        signatures[1] = _sign(g2Pk, digest);
        return abi.encode(signers, signatures);
    }

    function _scheduleDigest(address account, bytes32 salt, bytes32 mode, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(recovery.SCHEDULE_RECOVER_TYPEHASH(), address(recovery), salt, mode, keccak256(data))
        );
        return _domain(account, structHash);
    }

    function _cancelDigest(address account, bytes32 salt, bytes32 mode, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(recovery.CANCEL_RECOVER_TYPEHASH(), address(recovery), salt, mode, keccak256(data))
        );
        return _domain(account, structHash);
    }

    function _domain(address account, bytes32 structHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            Identity(payable(account)).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _addManagementKey(address account, address who) internal pure returns (bytes memory) {
        bytes memory callData = abi.encodeWithSignature(
            "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
            keccak256(abi.encodePacked(who)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(who),
            ""
        );
        return abi.encodePacked(account, uint256(0), callData);
    }

    function _installData(bytes[] memory guardians, uint64[] memory weights, uint64 threshold)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory executorArgs = abi.encodePacked(DELAY, EXPIRATION);
        bytes memory multisigArgs = abi.encode(guardians, threshold, weights);
        return abi.encodePacked(uint16(executorArgs.length), executorArgs, uint16(multisigArgs.length), multisigArgs);
    }

    function _guardians() internal view returns (bytes[] memory guardians) {
        guardians = new bytes[](3);
        guardians[0] = abi.encodePacked(g1);
        guardians[1] = abi.encodePacked(g2);
        guardians[2] = abi.encodePacked(g3);
    }

    function _weights(uint256 count) internal pure returns (uint64[] memory weights) {
        weights = new uint64[](count);
        for (uint256 i = 0; i < count; i++) {
            weights[i] = 1;
        }
    }

    function _hasManagement(address identity, address who) internal view returns (bool) {
        return IERC734(identity).keyHasPurpose(keccak256(abi.encodePacked(who)), KeyPurposes.MANAGEMENT);
    }

    function _state(address account, bytes32 salt, bytes32 mode, bytes memory data) internal view returns (uint8) {
        return uint8(recovery.state(account, salt, mode, data));
    }

}
