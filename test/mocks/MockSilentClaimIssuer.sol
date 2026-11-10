// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice ERC-7579 fallback handler an issuer's MANAGEMENT key can install in place of its
///         `isClaimValid` handler. It answers with no return data, which a high-level call
///         cannot decode. Used to prove that one such issuer cannot make a claim listing revert.
contract MockSilentClaimIssuer {

    function onInstall(bytes calldata) external { }

    function onUninstall(bytes calldata) external { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @notice Returns nothing at all.
    function isClaimValid(IIdentity, uint256, bytes calldata, Structs.ClaimData calldata) external pure { }

}
