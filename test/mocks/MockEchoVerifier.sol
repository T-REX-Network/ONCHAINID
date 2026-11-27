// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Returns its calldata unchanged, like the identity precompile at 0x04. The calldata of
///         a `verify` call starts with the `verify` selector, so the first returned word looks
///         like the magic value even though nothing was verified.
contract MockEchoVerifier {

    fallback(bytes calldata input) external returns (bytes memory) {
        return input;
    }

}
