// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice ERC-7579 fallback handler an issuer's MANAGEMENT key can install in place of its
///         `isClaimValid` handler. It answers with the word 2, which is neither true nor false.
///         Used to prove that such an answer is read as unknown, not as valid or invalid.
contract MockOutOfRangeClaimIssuer {

    uint256 private constant _NEITHER_TRUE_NOR_FALSE = 2;

    function onInstall(bytes calldata) external { }

    function onUninstall(bytes calldata) external { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @notice Returns one word that is not a valid bool.
    function isClaimValid(IIdentity, uint256, bytes calldata, Structs.ClaimData calldata)
        external
        pure
        returns (uint256)
    {
        return _NEITHER_TRUE_NOR_FALSE;
    }

}
