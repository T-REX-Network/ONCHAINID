// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { Execution, IERC7579Execution } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice M-10: a user op is paid from the identity's funds and uses up one of its nonces, so
///         only a key that can act for the identity (ACTION or MANAGEMENT) may sign one. Before
///         the fix, a key without signing authority could sign an empty batch: the per-call
///         ACTION check ran inside the batch loop, which an empty batch never enters.
///
///         In the fixture, `alice` holds MANAGEMENT on `aliceIdentity`, `david` holds ACTION and
///         `carol` holds CLAIM_SIGNER.
contract UserOpPurposeTest is OnchainIDSetup {

    /// @dev Same canonical EntryPoint the account trusts; see PrivilegedReentryGuard.t.sol.
    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    /// @dev Batch mode with the default exec type: CALLTYPE_BATCH (0x01) in the first byte.
    bytes32 internal constant BATCH_MODE = bytes32(bytes1(0x01));

    // ---- keys without signing authority --------------------------------------------------

    /// @notice The exploit from the report: a CLAIM_SIGNER key signs an empty batch.
    function test_claimSigner_cannotSendEmptyBatch() public {
        assertEq(_validate(carolPk, carol, _emptyBatch()), ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice The same holds for every purpose below ACTION, not only CLAIM_SIGNER.
    function test_everyPurposeBelowAction_cannotSendAUserOp() public {
        uint256[3] memory purposes = [KeyPurposes.CLAIM_ADDER, KeyPurposes.ENCRYPTION, KeyPurposes.PROPOSER];
        for (uint256 i = 0; i < purposes.length; i++) {
            (address signer, uint256 signerPk) = makeAddrAndKey(string.concat("key-", vm.toString(purposes[i])));
            vm.prank(alice);
            aliceIdentity.addKeyWithData(
                keccak256(abi.encodePacked(signer)), purposes[i], KeyTypes.ECDSA, abi.encodePacked(signer), ""
            );

            assertEq(_validate(signerPk, signer, _emptyBatch()), ERC4337Utils.SIG_VALIDATION_FAILED, "empty batch");
            assertEq(
                _validate(signerPk, signer, _singleCall(makeAddr("target"))),
                ERC4337Utils.SIG_VALIDATION_FAILED,
                "single call"
            );
        }
    }

    // ---- empty batches ---------------------------------------------------------------------

    /// @notice An empty batch runs nothing, so even an ACTION key may not send one.
    function test_actionKey_cannotSendEmptyBatch() public {
        assertEq(_validate(davidPk, david, _emptyBatch()), ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    // ---- what still works ------------------------------------------------------------------

    /// @notice An ACTION key still sends a batch of external calls.
    function test_actionKey_canStillSendABatch() public {
        Execution[] memory batch = new Execution[](1);
        batch[0] = Execution({ target: makeAddr("target"), value: 0, callData: "" });
        bytes memory callData = abi.encodeCall(IERC7579Execution.execute, (BATCH_MODE, abi.encode(batch)));

        assertEq(_validate(davidPk, david, callData), ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    /// @notice MANAGEMENT passes every user op, as before.
    function test_management_canStillSendAnyUserOp() public {
        assertEq(_validate(alicePk, alice, _emptyBatch()), ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    // ---- helpers ---------------------------------------------------------------------------

    function _emptyBatch() internal pure returns (bytes memory) {
        return abi.encodeCall(IERC7579Execution.execute, (BATCH_MODE, abi.encode(new Execution[](0))));
    }

    function _singleCall(address target) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC7579Execution.execute, (bytes32(0), abi.encodePacked(target, uint256(0), "")));
    }

    /// @dev Signs `callData` as a user op from `signer` and runs ERC-4337 validation on it.
    function _validate(uint256 signerPk, address signer, bytes memory callData) internal returns (uint256) {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, userOpHash);
        userOp.signature = abi.encode(abi.encodePacked(signer), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        return IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
    }

}
