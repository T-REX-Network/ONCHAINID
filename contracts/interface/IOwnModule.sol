// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

/// @title IOwnModule
/// @notice Lets anyone ask the account whether a target is one of its own installed modules. The
///         account uses this for its "a call may not re-enter my own modules" rule, and modules
///         like {KeyApprovalModule} ask the account instead of working it out again, so the two
///         always agree.
interface IOwnModule {

    /// @notice True if `target` is one of the account's own modules for a call with `selector`: an
    ///         installed executor, or the fallback handler for `selector`. Only MANAGEMENT may
    ///         call back into such a target.
    function isOwnModule(address target, bytes4 selector) external view returns (bool);

}
