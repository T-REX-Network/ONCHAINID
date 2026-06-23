// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Hash a 20-byte address the same way `keccak256(abi.encodePacked(addr))` does,
///         without going through the ABI encoder. Cheaper bytecode at every call site.
/// @dev `mstore` writes the address into the lower 20 bytes of slot 0 (with 12 leading
///      zero bytes of padding). We then hash only the address bytes by reading 20 bytes
///      starting at offset 12, which matches `abi.encodePacked(addr)` exactly.
function hashAddress(address input) pure returns (bytes32 hash) {
    assembly ("memory-safe") {
        mstore(0, input)
        hash := keccak256(12, 20)
    }
}
