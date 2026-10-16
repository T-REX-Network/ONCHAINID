// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { Execution } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title SafeCalldataBatch
/// @notice Calldata-preserving batch decoder that closes the cross-frame bounds gap in
///         OpenZeppelin's {ERC7579Utils-decodeBatch} without copying the batch into memory.
///
/// @dev    `ERC7579Utils.decodeBatch` bounds only the array's pointer region against the
///         `executionCalldata` slice; per-entry pointer resolution is left to Solidity's generated
///         calldata-array accessor, which bounds the resolved pointer against `calldatasize()` — the
///         enclosing frame, not the slice. When the same blob is decoded in two different frames
///         (the account entered as `execute`, the validator entered as `validateUserOp` with the
///         blob at an offset inside the re-encoded user operation), a backward-pointing entry can
///         resolve to different targets on each side, escalating a low-privilege key.
///
///         This helper re-runs `decodeBatch` and then walks every entry. A struct head that starts
///         before the slice, an `item + 0x60` that wraps, or a `callData` tail that wraps or leaves
///         the slice is rejected. The walk runs even when the slice is the last buffer in `msg.data`.
///         Solidity's lazy check does not catch a wrapped pointer there: the read comes back as
///         zeros and the account treats target 0 as itself. The batch stays in calldata. Ported
///         from OpenZeppelin PR #5400 (`ERC7579Utils._validateCalldataBound`), which the vendored
///         5.7.0-rc.0 predates, with the lower bound and the wrap checks that port was missing.
library SafeCalldataBatch {

    /// @dev Decodes a batch and validates every entry against the slice bounds. Reverts with
    ///      {ERC7579Utils.ERC7579DecodingError} on a malformed or out-of-bounds encoding.
    function decodeBatch(bytes calldata executionCalldata) internal pure returns (Execution[] calldata batch) {
        batch = ERC7579Utils.decodeBatch(executionCalldata);

        uint256 start;
        uint256 bound;
        assembly ("memory-safe") {
            start := executionCalldata.offset
            bound := add(start, executionCalldata.length)
        }
        _validateCalldataBound(batch, start, bound);
    }

    /// @dev Reject an entry unless its struct head and its `callData` tail both sit inside
    ///      `[start, bound]`, and neither `add` wrapped. `start` is `executionCalldata.offset`.
    ///      `bound` is that offset plus the slice length. The struct head is `item` for `0x60`
    ///      bytes. The tail includes its length word, which lives 32 bytes before the bytes.
    function _validateCalldataBound(Execution[] calldata batch, uint256 start, uint256 bound) private pure {
        for (uint256 i = 0; i < batch.length; ++i) {
            Execution calldata item = batch[i];
            bytes calldata itemCalldata = item.callData;

            uint256 itemOffset;
            uint256 itemEnd;
            uint256 itemCalldataOffset;
            uint256 itemCalldataEnd;
            assembly ("memory-safe") {
                itemOffset := item
                itemEnd := add(item, 0x60)
                itemCalldataOffset := itemCalldata.offset
                itemCalldataEnd := add(itemCalldata.offset, itemCalldata.length)
            }

            if (
                itemOffset < start || itemEnd < itemOffset || itemEnd > bound || itemCalldataOffset < start
                    || itemCalldataOffset < 0x20 || itemCalldataOffset - 0x20 < start
                    || itemCalldataEnd < itemCalldataOffset || itemCalldataEnd > bound
            ) {
                revert ERC7579Utils.ERC7579DecodingError();
            }
        }
    }

}
