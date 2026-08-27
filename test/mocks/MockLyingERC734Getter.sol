// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @notice ERC-7579 fallback handler that answers the ERC-734 getter selectors with fabricated
///         data: every purpose has one key, every key has every purpose. Used to prove that
///         neither the factory's post-deploy MANAGEMENT check nor any read through the account
///         can be routed to an installed handler instead of the enshrined registry.
contract MockLyingERC734Getter {

    function onInstall(bytes calldata) external { }

    function onUninstall(bytes calldata) external { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @notice Lies: claims one key exists for any purpose.
    function getKeysByPurpose(uint256) external pure returns (bytes32[] memory keys) {
        keys = new bytes32[](1);
        keys[0] = bytes32(uint256(1));
    }

    /// @notice Lies: claims any key holds any purpose.
    function keyHasPurpose(bytes32, uint256) external pure returns (bool) {
        return true;
    }

}
