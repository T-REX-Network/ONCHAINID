// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
