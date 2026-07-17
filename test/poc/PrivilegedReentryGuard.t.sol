// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockStockECDSAValidator } from "../mocks/MockStockECDSAValidator.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    Execution,
    IERC7579Execution,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";

/// @dev A trivial external target to prove ordinary ACTION calls still work.
contract PocCounter {

    uint256 public count;

    function increment() external {
        count++;
    }

}

/// @title Privileged re-entry guard
/// @notice The account must never let a call it dispatches re-enter one of its own installed
///         modules unless a privileged caller (the account itself, or a MANAGEMENT module)
///         drives it. The headline case: an ACTION signer must not be able to route a user op
///         through the installed {KeyApprovalModule} executor to grant itself MANAGEMENT.
///
///         The block lives in `SmartAccount._execute`, the single dispatch chokepoint both the
///         user-op `execute` path and `executeFromExecutor` funnel through. `validateUserOp` may
///         still pass (the validator sees the module as an ordinary external target), so these
///         tests drive execution end to end from the EntryPoint and assert the dispatch reverts.
contract PrivilegedReentryGuardTest is OnchainIDSetup {

    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    ERC734Validator internal validator; // the enshrined key registry for aliceIdentity
    KeyApprovalModule internal kam; // executor holding a MANAGEMENT module-key

    function setUp() public virtual override {
        super.setUp();
        // `legacyQueueModules` installs the enshrined registry as the validator and the
        // KeyApprovalModule as an executor with a MANAGEMENT module-key. `david` is seeded ACTION.
        validator = onchainidSetup.signatureValidator;
        kam = onchainidSetup.keyApprovalModule;
    }

    // --- helpers ---------------------------------------------------------

    function _davidKey() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(david));
    }

    function _singleExecute(address target, bytes memory innerCall) internal pure returns (bytes memory) {
        bytes memory executionCalldata = abi.encodePacked(target, uint256(0), innerCall);
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), executionCalldata);
    }

    /// @dev Dispatch `callData` on the account as the EntryPoint would after a validated user op.
    function _dispatchAsEntryPoint(bytes memory callData) internal {
        vm.prank(ENTRY_POINT);
        (bool ok, bytes memory ret) = address(aliceIdentity).call(callData);
        if (!ok) {
            // Bubble the revert reason so `vm.expectRevert` can match it.
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    // --- the exploit is blocked -----------------------------------------

    /// @notice The headline escalation: an ACTION key routes a user op through the installed KAM
    ///         executor to run `addKey(david, MANAGEMENT)`. The `_execute` guard rejects it, and
    ///         david never gains MANAGEMENT.
    function test_actionKey_cannotEscalate_viaKeyApprovalModule() public {
        assertTrue(validator.keyHasPurpose(address(aliceIdentity), _davidKey(), KeyPurposes.ACTION), "david is ACTION");

        bytes memory addMgmt = abi.encodeCall(
            ERC734Validator.addKey, (abi.encodePacked(david), "", KeyPurposes.MANAGEMENT, KeyTypes.ECDSA)
        );
        bytes memory innerKamCall = abi.encodeCall(KeyApprovalModule.execute, (address(validator), 0, addMgmt));
        bytes memory callData = _singleExecute(address(kam), innerKamCall);

        vm.expectRevert(abi.encodeWithSelector(Errors.PrivilegedTargetRequiresManagement.selector, address(kam)));
        _dispatchAsEntryPoint(callData);

        assertFalse(
            validator.keyHasPurpose(address(aliceIdentity), _davidKey(), KeyPurposes.MANAGEMENT),
            "david must not have escalated to MANAGEMENT"
        );
    }

    /// @notice Faithful reproduction of the original exploit: the `_data` handed to KAM is padded
    ///         so its trailing 20 bytes forge `david` as the ERC-2771 caller (the account does not
    ///         append a real tail on the direct-execute path). Pre-fix this escalated david to
    ///         MANAGEMENT; the `_execute` guard now rejects the call before KAM ever runs.
    function test_actionKey_cannotEscalate_viaKeyApprovalModule_forgedTail() public {
        bytes memory addMgmt = abi.encodeCall(
            ERC734Validator.addKey, (abi.encodePacked(david), "", KeyPurposes.MANAGEMENT, KeyTypes.ECDSA)
        );
        // Pad so that, once ABI-encoded as KAM.execute's last `bytes` arg, david's 20 bytes land as
        // the final 20 bytes of the calldata KAM sees, forging `_msgSender()` to david.
        uint256 padLen = (12 + 32 - (addMgmt.length % 32)) % 32;
        bytes memory forgedData = bytes.concat(addMgmt, new bytes(padLen), abi.encodePacked(david));

        bytes memory innerKamCall = abi.encodeCall(KeyApprovalModule.execute, (address(validator), 0, forgedData));
        bytes memory callData = _singleExecute(address(kam), innerKamCall);

        vm.expectRevert(abi.encodeWithSelector(Errors.PrivilegedTargetRequiresManagement.selector, address(kam)));
        _dispatchAsEntryPoint(callData);

        assertFalse(
            validator.keyHasPurpose(address(aliceIdentity), _davidKey(), KeyPurposes.MANAGEMENT),
            "forged-tail escalation must be blocked"
        );
    }

    /// @notice The same guard covers a fallback handler as a target: `addClaim` is served by the
    ///         validator via fallback, so a user op that targets the validator directly is a
    ///         privileged-module re-entry and is rejected.
    function test_actionKey_cannotTargetFallbackHandlerModule() public {
        bytes memory addMgmt = abi.encodeCall(
            ERC734Validator.addKey, (abi.encodePacked(david), "", KeyPurposes.MANAGEMENT, KeyTypes.ECDSA)
        );
        bytes memory callData = _singleExecute(address(validator), addMgmt);

        vm.expectRevert(abi.encodeWithSelector(Errors.PrivilegedTargetRequiresManagement.selector, address(validator)));
        _dispatchAsEntryPoint(callData);
    }

    /// @notice A batch that mixes a legitimate external call with a privileged re-entry fails as a
    ///         whole; the guard checks every sub-call.
    function test_batch_withPrivilegedTarget_rejected() public {
        PocCounter counter = new PocCounter();
        bytes memory addMgmt = abi.encodeCall(
            ERC734Validator.addKey, (abi.encodePacked(david), "", KeyPurposes.MANAGEMENT, KeyTypes.ECDSA)
        );

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(address(counter), 0, abi.encodeCall(PocCounter.increment, ()));
        batch[1] =
            Execution(address(kam), 0, abi.encodeCall(KeyApprovalModule.execute, (address(validator), 0, addMgmt)));

        bytes memory callData = abi.encodeWithSelector(
            IERC7579Execution.execute.selector, bytes32(uint256(0x01) << 248), ERC7579Utils.encodeBatch(batch)
        );

        vm.expectRevert(abi.encodeWithSelector(Errors.PrivilegedTargetRequiresManagement.selector, address(kam)));
        _dispatchAsEntryPoint(callData);
    }

    /// @notice DELEGATECALL is rejected outright: the account must never run foreign code in its
    ///         own context.
    function test_delegatecall_rejected() public {
        PocCounter counter = new PocCounter();
        bytes memory executionCalldata = abi.encodePacked(address(counter), abi.encodeCall(PocCounter.increment, ()));
        // CALLTYPE_DELEGATECALL is 0xFF in the leading byte of the mode word.
        bytes32 mode = bytes32(uint256(0xFF) << 248);
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionCalldata);

        vm.expectRevert(abi.encodeWithSelector(Errors.UnsupportedExecutionMode.selector, mode));
        _dispatchAsEntryPoint(callData);
    }

    // --- legitimate flows still work ------------------------------------

    /// @notice Regression: a plain ACTION call to an ordinary external target still dispatches.
    function test_actionKey_externalTarget_stillWorks() public {
        PocCounter counter = new PocCounter();
        bytes memory callData = _singleExecute(address(counter), abi.encodeCall(PocCounter.increment, ()));

        _dispatchAsEntryPoint(callData);
        assertEq(counter.count(), 1, "ordinary external ACTION call must still run");
    }

    /// @notice Regression: MANAGEMENT reaching an installed module through a self-call is allowed
    ///         (the account itself is a privileged caller).
    function test_selfCall_management_canTargetModule() public {
        bytes memory addKeyData =
            abi.encodeCall(ERC734Validator.addKey, (abi.encodePacked(bob), "", KeyPurposes.ACTION, KeyTypes.ECDSA));
        bytes memory callData = _singleExecute(address(validator), addKeyData);

        // A self-call: msg.sender == the account, so the guard treats it as privileged.
        vm.prank(address(aliceIdentity));
        (bool ok,) = address(aliceIdentity).call(callData);
        assertTrue(ok, "MANAGEMENT self-call into a module must be allowed");
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), keccak256(abi.encodePacked(bob)), KeyPurposes.ACTION),
            "self-call addKey should have registered bob"
        );
    }

    // --- KeyApprovalModule policy agrees with the account ---------------

    /// @notice KAM's auto-approval table must also refuse a module target for an ACTION key, so the
    ///         two surfaces stay in step.
    function test_kam_canAutoApprove_refusesModuleTarget() public {
        bytes memory anyData = abi.encodeCall(PocCounter.increment, ());
        vm.prank(address(aliceIdentity));
        bool approved = kam.canAutoApprove(address(aliceIdentity), _davidKey(), address(kam), anyData);
        assertFalse(approved, "ACTION must not auto-approve a call into an installed module");
    }

    /// @notice KAM must also refuse a target that is only a FALLBACK handler (not an executor), so
    ///         its auto-approval table can never be looser than the account's re-entry guard.
    function test_kam_canAutoApprove_refusesFallbackOnlyModuleTarget() public {
        DummyFallback handler = new DummyFallback();
        // Install it as a fallback-only handler for its own selector (no executor install).
        vm.prank(alice);
        aliceIdentity.installModule(
            MODULE_TYPE_FALLBACK, address(handler), abi.encodePacked(DummyFallback.ping.selector)
        );

        bytes memory pingData = abi.encodeCall(DummyFallback.ping, ());
        vm.prank(address(aliceIdentity));
        bool approved = kam.canAutoApprove(address(aliceIdentity), _davidKey(), address(handler), pingData);
        assertFalse(approved, "ACTION must not auto-approve a call into a fallback-only module");
    }

    // --- validators-as-keys trust model (documented, not a gap) ---------

    /// @notice Locks in the validators-as-keys trust model. A stock validator does not restrict its
    ///         signers, and the account trusts whatever the validator accepted, so a stock
    ///         validator's signer can reach self calls like addKey. This is intended (see
    ///         {SmartAccount.installModule}); installing that validator already needed MANAGEMENT.
    ///         The real {ERC734Validator} restricts self calls, so live identities are fine.
    function test_stockValidator_signerCanSelfModify_byDesign() public {
        // Installing the stock validator itself requires MANAGEMENT (alice).
        MockStockECDSAValidator stock = new MockStockECDSAValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(stock), abi.encodePacked(david));

        // david (only ACTION on the account) signs a self-target addKey(david, MANAGEMENT).
        bytes memory inner = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", _davidKey(), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );
        bytes memory callData = _singleExecute(address(aliceIdentity), inner);
        uint256 nonce = uint256(uint160(address(stock))) << 96;
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: nonce,
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
        userOp.signature = abi.encodePacked(r, s, v); // stock validator wants a raw 65-byte sig

        vm.prank(ENTRY_POINT);
        assertEq(
            IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0),
            ERC4337Utils.SIG_VALIDATION_SUCCESS,
            "stock validator vouches; account does not re-scope"
        );

        _dispatchAsEntryPoint(callData);
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), _davidKey(), KeyPurposes.MANAGEMENT),
            "documented trust model: an unscoped stock validator's signer can self-modify"
        );
    }

}

/// @dev A minimal ERC-7579 fallback handler used to exercise the fallback-only target branch.
contract DummyFallback {

    function ping() external pure returns (uint256) {
        return 1;
    }

    function onInstall(bytes calldata) external pure { }

    function onUninstall(bytes calldata) external pure { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 3; // MODULE_TYPE_FALLBACK
    }

}
