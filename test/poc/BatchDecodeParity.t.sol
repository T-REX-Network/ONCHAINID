// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { hashAddress } from "contracts/libraries/Hashing.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";

/// @notice Regression coverage for validator/executor batch-decode parity.
///
///         `ERC734Validator._scopeAllows` and `SmartAccount._execute` decode the same
///         `executionCalldata` independently. While both used `ERC7579Utils.decodeBatch`, per-entry
///         pointer validation was deferred to Solidity's generated calldata-array accessor, which
///         bounds the resolved pointer against `calldatasize()` of the enclosing frame. The two
///         frames differ: the account is entered as `execute`, where the blob is all of calldata,
///         while the validator is entered as `validateUserOp`, where the same blob sits at an
///         offset inside the re-encoded user operation. An entry pointer aimed backwards therefore
///         resolved to a nonzero external target during validation, where an ACTION key suffices,
///         and to `target == 0` during execution, which is aliased to the account itself. The
///         result was a self-call carrying attacker-chosen calldata, escalating an ACTION key to
///         MANAGEMENT.
///
///         Both sites now decode with `abi.decode(..., (Execution[]))`, which copies into memory
///         and validates every pointer against that copy, so the crafted batch is rejected and the
///         two sides cannot disagree. This test fails before that change and passes after it.
contract BatchDecodeParityTest is OnchainIDSetup {

    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function _writeWord(bytes memory b, uint256 at, uint256 v) internal pure {
        for (uint256 i = 0; i < 32; i++) {
            b[at + i] = bytes1(uint8(v >> (8 * (31 - i))));
        }
    }

    function _writeBytes(bytes memory b, uint256 at, bytes memory src) internal pure {
        for (uint256 i = 0; i < src.length; i++) {
            b[at + i] = src[i];
        }
    }

    /// @dev Builds a batch whose single entry pointer resolves outside `executionCalldata`.
    ///      Offsets are absolute in the account frame, where `calldatasize == blob.length`:
    ///        [0..3]     selector for execute(bytes32,bytes)
    ///        [4..35]    mode: callType = 0x01 (BATCH), execType = 0x00, rest zero
    ///        [36..67]   dataOffset = 64
    ///        [68..99]   dataLen    = 96
    ///        [100..195] executionCalldata: arrayLengthOffset = 0x20, arrayLength = 1, entryPtr
    ///        [16357..]  planted length word for the escaped Execution.callData tail
    ///        [16389..]  planted payload bytes
    ///      base (executionBatch.offset) = 100 + 0x20 + 0x20 = 164. `rel` is chosen so the struct
    ///      pointer wraps to 2**256 - 27. In the account frame every struct-head read is then out
    ///      of range, giving target 0, while addr + 0x40 wraps to blob offset 37, which holds
    ///      0x4000 (16384), so the callData tail lands on the planted bytes. In the validator
    ///      frame addr + 420 = 393 lands inside the re-encoded userOp head and reads nonzero
    ///      garbage, which scans as an ordinary external target.
    function _crossFrameBatch(bytes memory payload) internal pure returns (bytes memory blob) {
        uint256 lengthWordAt = 16357;
        uint256 payloadAt = lengthWordAt + 32;
        blob = new bytes(payloadAt + payload.length);

        blob[0] = 0xe9;
        blob[1] = 0xae;
        blob[2] = 0x5c;
        blob[3] = 0x53;
        blob[4] = 0x01; // CALLTYPE_BATCH
        _writeWord(blob, 36, 64); // dataOffset
        _writeWord(blob, 68, 96); // dataLen
        _writeWord(blob, 100, 0x20); // arrayLengthOffset
        _writeWord(blob, 132, 1); // arrayLength
        uint256 rel;
        unchecked {
            rel = uint256(0) - 27 - 164; // entry pointer, deliberately negative
        }
        _writeWord(blob, 164, rel);
        _writeWord(blob, lengthWordAt, payload.length);
        _writeBytes(blob, payloadAt, payload);
    }

    function _userOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: address(aliceIdentity),
            // High 160 bits select the validator, per the ERC-7579 nonce encoding.
            nonce: (uint256(uint160(address(onchainidSetup.signatureValidator))) << 96),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    /// @notice A batch entry pointing outside `executionCalldata` must be rejected during
    ///         validation and must never escalate the signer's key.
    function test_batchEntryOutsideSlice_rejectedAndCannotEscalate() public {
        bytes32 davidKey = hashAddress(david);

        // Preconditions asserted rather than assumed: an ACTION-only signer.
        assertTrue(_has(davidKey, KeyPurposes.ACTION), "david holds ACTION");
        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT), "david must not hold MANAGEMENT before");

        // The payload the escaped Execution.callData tail is aimed at: a self-call granting
        // MANAGEMENT to the ACTION-key holder.
        bytes memory payload =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", davidKey, uint256(1), uint256(1));

        PackedUserOperation memory op = _userOp(_crossFrameBatch(payload));
        bytes32 userOpHash = keccak256("cross-frame-batch");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        op.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

        // Decoding the malformed batch into memory reverts, so the operation is rejected rather
        // than approved against a target the account would not run.
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        IAccount(address(aliceIdentity)).validateUserOp(op, userOpHash, 0);

        // The account must refuse the same bytes on the execution path too.
        vm.prank(ENTRY_POINT);
        (bool executed,) = address(aliceIdentity).call(op.callData);
        assertFalse(executed, "the account must not execute the crafted batch");

        // Whatever happened above, no escalation may have occurred.
        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT), "ACTION key must not gain MANAGEMENT");
    }

    function _has(bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        return ERC734Validator(address(onchainidSetup.signatureValidator))
            .keyHasPurpose(address(aliceIdentity), keyHash, purpose);
    }

}
