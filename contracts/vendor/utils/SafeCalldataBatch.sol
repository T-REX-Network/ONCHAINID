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
///         This helper re-runs `decodeBatch` and then, only when `executionCalldata` is not the last
///         buffer in `msg.data` (the exact case Solidity's lazy checks miss), walks every entry and
///         rejects any whose struct head or `callData` tail escapes the slice. The batch stays in
///         calldata, so callers keep OZ's gas profile. Ported from OpenZeppelin PR #5400
///         (`ERC7579Utils._validateCalldataBound`), which the vendored 5.7.0-rc.0 predates.
library SafeCalldataBatch {

    /// @dev Decodes a batch and validates every entry against the slice bounds. Reverts with
    ///      {ERC7579Utils.ERC7579DecodingError} on a malformed or out-of-bounds encoding.
    function decodeBatch(bytes calldata executionCalldata) internal pure returns (Execution[] calldata batch) {
        batch = ERC7579Utils.decodeBatch(executionCalldata);

        uint256 bound;
        assembly ("memory-safe") {
            bound := add(executionCalldata.offset, executionCalldata.length)
        }
        _validateCalldataBound(batch, bound);
    }

    /// @dev In-depth sanity check. Solidity verifies calldata objects lazily, bounding them against
    ///      `calldatasize()` when they are dereferenced. If `executionCalldata` is not the last buffer
    ///      in `msg.data`, that lazy check does not catch entries pointing into the space past the
    ///      slice but still inside the frame. When the slice ends before `msg.data`, traverse the
    ///      array and reject any entry whose struct head (`target|value|callData-offset`, 0x60 bytes)
    ///      or `callData` tail extends beyond `bound`.
    function _validateCalldataBound(Execution[] calldata batch, uint256 bound) private pure {
        if (bound < msg.data.length) {
            for (uint256 i = 0; i < batch.length; ++i) {
                Execution calldata item = batch[i];
                bytes calldata itemCalldata = item.callData;

                uint256 itemEnd;
                uint256 itemCalldataEnd;
                assembly ("memory-safe") {
                    itemEnd := add(item, 0x60)
                    itemCalldataEnd := add(itemCalldata.offset, itemCalldata.length)
                }
                if (itemEnd > bound || itemCalldataEnd > bound) revert ERC7579Utils.ERC7579DecodingError();
            }
        }
    }

}
