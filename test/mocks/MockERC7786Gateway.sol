// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC7786Recipient } from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";

/// @title MockERC7786Gateway
/// @notice Test stand-in for a real ERC-7786 destination gateway. In production a
///         gateway authenticates an inbound message from its underlying transport
///         (CCIP, Hyperlane, native bridge, ...) before invoking the recipient.
///         For tests we skip the transport and let the test author craft the
///         `sender` envelope and payload directly.
contract MockERC7786Gateway {

    /// @notice Forward a synthetic cross-chain message to a recipient. The recipient
    ///         is expected to authorize this contract as a trusted gateway and then
    ///         decode the payload itself.
    function deliver(address recipient, bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        external
        returns (bytes4)
    {
        return IERC7786Recipient(recipient).receiveMessage(receiveId, sender, payload);
    }

}
