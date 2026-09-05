// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

/// @dev Events shared across the identity stack.
library Events {

    /// @dev Emitted first in every gated function whose caller is
    event CalledBy(address caller, bytes4 selector);

}
