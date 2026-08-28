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

/// @title KeyPurposes
/// @notice Constants for Key Purposes
library KeyPurposes {

    /// @dev 1: MANAGEMENT keys, which can manage the identity
    uint256 internal constant MANAGEMENT = 1;

    /// @dev 2: ACTION keys, which perform actions in this identities name (signing, logins, transactions, etc.)
    uint256 internal constant ACTION = 2;

    /// @dev 3: CLAIM signer keys, used to sign claims on other identities which need to be revokable.
    uint256 internal constant CLAIM_SIGNER = 3;

    /// @dev 4: ENCRYPTION keys, used to encrypt data e.g. hold in claims.
    uint256 internal constant ENCRYPTION = 4;

    /// @dev 5: CLAIM_ADDER key, can add claims but cannot remove them.
    uint256 internal constant CLAIM_ADDER = 5;

    /// @dev 6: PROPOSER keys can queue executions on the identity but cannot auto-run
    ///      or self-approve them. Used to raise the floor on who can push entries onto
    ///      the execution queue without expanding any auto-approval rule.
    uint256 internal constant PROPOSER = 6;

}
