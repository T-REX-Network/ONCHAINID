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

/// @title IdentityTypes
/// @notice Constants for Identity Types
library IdentityTypes {

    /// @dev 1: ASSET identity, used for token identities
    uint256 internal constant ASSET = 1;

    /// @dev 2: INDIVIDUAL identity
    uint256 internal constant INDIVIDUAL = 2;

    /// @dev 3: CORPORATE identity
    uint256 internal constant CORPORATE = 3;

    /// @dev 4: IOT identity
    uint256 internal constant IOT = 4;

    /// @dev 5: CLAIM_ISSUER identity
    uint256 internal constant CLAIM_ISSUER = 5;

    /// @dev 6: SMART_CONTRACT identity (DeFi protocols, vaults, bridges, escrows, etc.)
    uint256 internal constant SMART_CONTRACT = 6;

    /// @dev 7: PUBLIC_AUTHORITY identity (regulators, courts, government issuers, etc.)
    uint256 internal constant PUBLIC_AUTHORITY = 7;

    /// @dev 8: AI_AGENT identity
    uint256 internal constant AI_AGENT = 8;

}
