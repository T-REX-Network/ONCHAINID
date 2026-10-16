// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { hashAddress } from "contracts/libraries/Hashing.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";

/// @notice The inside-slice sibling of {BatchDecodeParityTest}.
///
///         Both tests plant an `addKey` at the end of an `execute` blob and point the single batch
///         entry backwards so the pointer wraps. `BatchDecodeParityTest` declares a 96-byte slice,
///         so the planted tail sits past that slice and the old bounds walk still runs.
///
///         This test declares the slice as the rest of the blob. On the account frame the slice
///         then ends at `msg.data`, the old walk is skipped, and the wrapped read comes back as
///         target 0, which the account treats as itself. On the validator frame the same struct
///         head starts before the execution slice, and the old walk had no lower bound, so it
///         authorizes a different target than execution runs. An ACTION key could therefore grant
///         itself MANAGEMENT.
///
///         Both sites now copy the batch with `abi.decode`, which reverts on this pointer. The
///         key stays ACTION. `abi.decode` reverts with an empty reason, so the assertions do not
///         match a selector.
contract WrappedBatchEscalationTest is OnchainIDSetup {

    /// @dev Canonical EntryPoint. `validateUserOp` only accepts this caller.
    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    /// @dev Where the planted `callData` length word sits in the account frame.
    uint256 internal constant LENGTH_WORD_AT = 16357;

    /// @dev Where the wrapped entry offset is written. This is also where the execution batch
    ///      starts once `executionCalldata` begins at byte 100 and its head is `0x20`.
    uint256 internal constant ENTRY_OFFSET_AT = 164;

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

    /// @dev One `execute(bytes32,bytes)` blob whose batch entry wraps, with the planted tail
    ///      inside the declared slice.
    ///
    ///        [0..3]      execute(bytes32,bytes)
    ///        [4..35]     mode, callType BATCH (`0x01`)
    ///        [36..67]    offset to the `bytes` argument, 64
    ///        [68..99]    length of that argument: the rest of the blob, so the slice includes the tail
    ///        [100..131]  offset to the `Execution[]` head, `0x20`
    ///        [132..163]  one entry
    ///        [164..195]  entry offset `2**256 - 191`, which wraps to `2**256 - 27`
    ///        [16357..]   length of the planted `addKey` calldata
    ///        [16389..]   the `addKey` bytes
    function _wrappingBatch(bytes memory payload) internal pure returns (bytes memory blob) {
        uint256 payloadAt = LENGTH_WORD_AT + 32;
        blob = new bytes(payloadAt + payload.length);

        blob[0] = 0xe9;
        blob[1] = 0xae;
        blob[2] = 0x5c;
        blob[3] = 0x53;
        blob[4] = 0x01;
        _writeWord(blob, 36, 64);
        // Byte 100 is where `executionCalldata` starts. A length of `blob.length - 100` makes the
        // slice run to the end of the blob, so the tail at `LENGTH_WORD_AT` is inside it.
        _writeWord(blob, 68, blob.length - 100);
        _writeWord(blob, 100, 0x20);
        _writeWord(blob, 132, 1);
        uint256 wrappedEntry;
        unchecked {
            // `0 - 27 - 164`. From byte 164 this resolves to absolute `2**256 - 27`.
            wrappedEntry = uint256(0) - 27 - ENTRY_OFFSET_AT;
        }
        _writeWord(blob, ENTRY_OFFSET_AT, wrappedEntry);
        _writeWord(blob, LENGTH_WORD_AT, payload.length);
        _writeBytes(blob, payloadAt, payload);
    }

    /// @dev A user operation whose call data is the crafted blob. The nonce selects the account's
    ///      ERC-734 validator. The signature is filled in by the test.
    function _userOp(bytes memory callData) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: address(aliceIdentity),
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

    function _has(bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        return ERC734Validator(address(onchainidSetup.signatureValidator))
            .keyHasPurpose(address(aliceIdentity), keyHash, purpose);
    }

    /// @notice An ACTION key cannot turn a wrapping, in-slice batch pointer into MANAGEMENT.
    function test_wrappedEntryInsideSlice_actionKeyDoesNotBecomeManager() public {
        bytes32 davidKey = hashAddress(david);
        assertTrue(_has(davidKey, KeyPurposes.ACTION), "david holds ACTION");
        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT), "david must not hold MANAGEMENT before");

        // Purpose 1 is MANAGEMENT. Key type 1 is ECDSA. On the unfixed account this self-call lands.
        bytes memory payload =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", davidKey, uint256(1), uint256(1));
        PackedUserOperation memory op = _userOp(_wrappingBatch(payload));

        bytes32 userOpHash = keccak256("wrapped-batch-inside-slice");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        op.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

        // Validator frame. `validateUserOp` decodes the batch and must revert before it returns success.
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        IAccount(address(aliceIdentity)).validateUserOp(op, userOpHash, 0);

        // Account frame. The same bytes, sent as the whole call, must not run.
        vm.prank(ENTRY_POINT);
        (bool executed,) = address(aliceIdentity).call(op.callData);
        assertFalse(executed, "the account must not execute the crafted batch");

        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT), "ACTION key must not gain MANAGEMENT");
    }

}
