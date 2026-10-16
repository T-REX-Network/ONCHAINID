// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { Execution } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { hashAddress } from "contracts/libraries/Hashing.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { SafeCalldataBatch } from "contracts/vendor/utils/SafeCalldataBatch.sol";

contract WrappedBatchProbe {

    fallback(bytes calldata) external returns (bytes memory) {
        (address target, uint256 value, bytes memory callData) = _decode(msg.data);
        return abi.encode(target, value, callData);
    }

    function validatorFrame(PackedUserOperation calldata userOp, bytes32)
        external
        pure
        returns (address target, uint256 value, bytes memory callData)
    {
        return _decode(userOp.callData);
    }

    function _decode(bytes calldata cd) private pure returns (address target, uint256 value, bytes memory callData) {
        uint256 dataOffset = uint256(bytes32(cd[36:68]));
        uint256 lenPos = 4 + dataOffset;
        uint256 dataLen = uint256(bytes32(cd[lenPos:lenPos + 32]));
        uint256 dataStart = lenPos + 32;
        Execution[] calldata batch = SafeCalldataBatch.decodeBatch(cd[dataStart:dataStart + dataLen]);
        Execution calldata item = batch[0];
        return (item.target, item.value, item.callData);
    }

}

contract WrappedBatchEscalationTest is OnchainIDSetup {

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

    function _wrappingBatch(bytes memory payload) internal pure returns (bytes memory blob) {
        uint256 lengthWordAt = 16357;
        uint256 payloadAt = lengthWordAt + 32;
        blob = new bytes(payloadAt + payload.length);

        blob[0] = 0xe9;
        blob[1] = 0xae;
        blob[2] = 0x5c;
        blob[3] = 0x53;
        blob[4] = 0x01;
        _writeWord(blob, 36, 64);
        _writeWord(blob, 68, blob.length - 100);
        _writeWord(blob, 100, 0x20);
        _writeWord(blob, 132, 1);
        uint256 rel;
        unchecked {
            rel = uint256(0) - 27 - 164;
        }
        _writeWord(blob, 164, rel);
        _writeWord(blob, lengthWordAt, payload.length);
        _writeBytes(blob, payloadAt, payload);
    }

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

    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4);
        assembly ("memory-safe") {
            sel := mload(add(reason, 32))
        }
    }

    function test_wrappedEntryInsideSlice_actionKeyDoesNotBecomeManager() public {
        bytes32 davidKey = hashAddress(david);
        assertTrue(_has(davidKey, KeyPurposes.ACTION));
        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT));

        bytes memory payload =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", davidKey, uint256(1), uint256(1));
        bytes memory blob = _wrappingBatch(payload);

        WrappedBatchProbe probe = new WrappedBatchProbe();
        (bool accountOk, bytes memory accountRet) = address(probe).call(blob);
        assertFalse(accountOk);
        assertEq(_selector(accountRet), ERC7579Utils.ERC7579DecodingError.selector);

        PackedUserOperation memory op = _userOp(blob);
        vm.expectRevert(ERC7579Utils.ERC7579DecodingError.selector);
        probe.validatorFrame(op, bytes32(0));

        bytes32 userOpHash = keccak256("wrapped-batch-inside-slice");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(davidPk, userOpHash);
        op.signature = abi.encode(abi.encodePacked(david), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        vm.expectRevert(ERC7579Utils.ERC7579DecodingError.selector);
        IAccount(address(aliceIdentity)).validateUserOp(op, userOpHash, 0);

        vm.prank(ENTRY_POINT);
        (bool executed, bytes memory reason) = address(aliceIdentity).call(blob);
        assertFalse(executed);
        assertEq(_selector(reason), ERC7579Utils.ERC7579DecodingError.selector);
        assertFalse(_has(davidKey, KeyPurposes.MANAGEMENT));
    }

}
