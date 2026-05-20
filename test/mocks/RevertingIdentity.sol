// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Mock identity whose initialize always reverts, causing IdentityProxy CREATE3 to fail
contract RevertingIdentity {

    function initialize(address) external pure {
        revert("forced revert");
    }

}
