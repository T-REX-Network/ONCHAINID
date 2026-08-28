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

import { Structs } from "../storage/Structs.sol";
import { IERC734 } from "./IERC734.sol";
import { IERC735 } from "./IERC735.sol";

// solhint-disable-next-line no-empty-blocks
interface IIdentity is IERC734, IERC735 {

    /**
     * @dev Checks if a claim is valid.
     * @param _identity the identity contract related to the claim
     * @param claimTopic the claim topic of the claim
     * @param sig the signature of the claim
     * @param data the structured claim data
     * @return claimValid true if the claim is valid, false otherwise
     */
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, Structs.ClaimData calldata data)
        external
        view
        returns (bool);

    /**
     * @dev Computes the EIP-712 claim digest for off-chain signing.
     * @param _identity The identity address the claim is for
     * @param _topic The claim topic
     * @param _data The structured claim data
     * @return The EIP-712 typed data hash
     */
    function getClaimHash(address _identity, uint256 _topic, Structs.ClaimData memory _data)
        external
        view
        returns (bytes32);

    /**
     * @dev Returns the identity type set at initialization.
     * @return The identity type (see IdentityTypes library)
     */
    function getIdentityType() external view returns (uint256);

}
