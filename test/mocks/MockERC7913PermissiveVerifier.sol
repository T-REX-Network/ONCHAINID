// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";

/// @notice Mock ERC-7913 verifier that accepts any key, hash and signature
contract MockERC7913PermissiveVerifier is IERC7913SignatureVerifier {

    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        return IERC7913SignatureVerifier.verify.selector;
    }

}
