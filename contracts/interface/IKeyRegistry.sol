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

pragma solidity ^0.8.28;

/// @title IKeyRegistry
/// @notice The functions an identity calls on its key registry (the enshrined {ERC734Validator}).
///         The account and the factory reach the registry only through this interface, so its
///         ERC-165 id names exactly what an implementation needs from the registry.
/// @dev Changing any of these signatures changes the interface id. A registry deployed before
///      the change does not answer the new id, so the factory refuses to put an implementation
///      that needs it behind the beacon (see {IdentityFactory-upgradeBeacon}).
interface IKeyRegistry {

    /// @notice Register `signerData` as a key of the caller, with `purpose`.
    function addKey(
        bytes calldata signerData,
        bytes calldata clientData,
        uint256 purpose,
        uint256 keyType,
        address caller
    ) external;

    /// @notice Remove `purpose` from the caller's key `keyHash`.
    function removeKey(bytes32 keyHash, uint256 purpose, address caller) external;

    /// @notice The signer and client data of `account`'s key `keyHash`.
    function getKeyData(address account, bytes32 keyHash)
        external
        view
        returns (bytes memory signerData, bytes memory clientData);

    /// @notice `IERC734.getKey` for `account`.
    function getKey(address account, bytes32 keyHash)
        external
        view
        returns (uint256[] memory purposes, uint256 keyType, bytes32 key);

    /// @notice The purposes of `account`'s key `keyHash`.
    function getKeyPurposes(address account, bytes32 keyHash) external view returns (uint256[] memory);

    /// @notice The purposes of `account`'s key `keyHash`, in the index range `[start, end)`.
    function getKeyPurposes(address account, bytes32 keyHash, uint256 start, uint256 end)
        external
        view
        returns (uint256[] memory);

    /// @notice The keys of `account` with `purpose`.
    function getKeysByPurpose(address account, uint256 purpose) external view returns (bytes32[] memory);

    /// @notice The keys of `account` with `purpose`, in the index range `[start, end)`.
    function getKeysByPurpose(address account, uint256 purpose, uint256 start, uint256 end)
        external
        view
        returns (bytes32[] memory);

    /// @notice Whether `account`'s key `keyHash` has `purpose`. MANAGEMENT satisfies any purpose.
    function keyHasPurpose(address account, bytes32 keyHash, uint256 purpose) external view returns (bool);

}
