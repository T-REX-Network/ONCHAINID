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

/**
 * @dev Interface of the ERC734 (Key Holder) standard as defined in the EIP, registry-only.
 *
 * @notice The original `execute(address,uint256,bytes)` and `approve(uint256,bool)` selectors
 *         live in the {KeyApprovalModule} (an ERC-7579 fallback handler + executor). They are
 *         still reachable on every Identity at the standard ERC-734 selectors via the account's
 *         fallback, but they live behind a separate Solidity type — {IKeyExecutor} — to keep
 *         the registry interface decoupled from the execution surface.
 *
 *         See {IKeyExecutor} for the queue ABI, and {KeyApprovalModule} for the implementation.
 *
 *         Note on events: this interface declares none. The key registry and the execution
 *         queue are served by module singletons shared across identities, so the canonical
 *         ERC-734 events (which carry no subject) could not attribute a log to an identity.
 *         The real event ABI is the account-carrying variants — `KeyAdded` / `KeyRemoved` on
 *         {ERC734Validator} and the execution lifecycle events on {IKeyExecutor} — each with
 *         `address indexed account` (the identity) as its first field.
 */
interface IERC734 {

    /**
     * @dev Adds a _key to the identity. MUST only be done by keys of purpose MANAGEMENT,
     * or the identity itself.
     */
    function addKey(bytes32 _key, uint256 _purpose, uint256 _keyType) external returns (bool success);

    /**
     * @dev Removes _purpose for _key from the identity. MUST only be done by keys of purpose
     * MANAGEMENT, or the identity itself.
     */
    function removeKey(bytes32 _key, uint256 _purpose) external returns (bool success);

    /// @dev Returns the full key data, if present.
    function getKey(bytes32 _key) external view returns (uint256[] memory purposes, uint256 keyType, bytes32 key);

    /// @dev Returns the purposes for a key.
    function getKeyPurposes(bytes32 _key) external view returns (uint256[] memory _purposes);

    /// @dev Returns the key hashes registered with a given purpose.
    function getKeysByPurpose(uint256 _purpose) external view returns (bytes32[] memory keys);

    /// @dev Returns TRUE if a key has the given purpose, or MANAGEMENT (universal).
    function keyHasPurpose(bytes32 _key, uint256 _purpose) external view returns (bool exists);

}
