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

/// @title KeyTypes
/// @notice Constants for Key Types
library KeyTypes {

    /// @dev 1: ECDSA
    uint256 internal constant ECDSA = 1;

    /// @dev 2: RSA
    uint256 internal constant RSA = 2;

    /// @dev 3: WEBAUTHN (P-256 / secp256r1 via WebAuthn ceremony, ERC-7913)
    uint256 internal constant WEBAUTHN = 3;

    /// @dev 4: MODULE. Used for executor modules only (gates `executeFromExecutor`).
    ///      Not used for validators. Validators address signers, not modules.
    uint256 internal constant MODULE = 4;

    /// @dev 5: ACCESS_MANAGER. Signer is an OpenZeppelin AccessManager. Used to govern
    ///      an identity through roles instead of a single key. Intended purpose: MANAGEMENT.
    uint256 internal constant ACCESS_MANAGER = 5;

}
