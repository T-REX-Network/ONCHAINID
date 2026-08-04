// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @title ISmartAccount
/// @notice Account-side dispatch policy read by executor modules.
interface ISmartAccount {

    /// @notice Whether a call to `target` needs MANAGEMENT rather than ACTION: the account itself,
    ///         or its factory (whose wallet-binding calls change the identity's own bindings).
    function isManagementTarget(address target) external view returns (bool);

}
