// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice A claim issuer that accepts every claim and answers `eip712Domain()` with data that
///         does not decode as an EIP-712 domain. `mode` picks how the answer is broken.
contract MockMalformedDomainIssuer {

    enum Mode {
        TooShort, // one word instead of seven
        BadStringOffset // seven words, but the `name` offset points past the end
    }

    Mode public mode;

    function setMode(Mode newMode) external {
        mode = newMode;
    }

    /// @dev Accepts every claim.
    function isClaimValid(IIdentity, uint256, bytes calldata, Structs.ClaimData calldata) external pure returns (bool) {
        return true;
    }

    /// @dev Same selector as `IERC5267.eip712Domain`, with a broken answer.
    function eip712Domain() external view returns (bytes memory) {
        bytes memory answer = mode == Mode.TooShort
            ? abi.encode(bytes32(0))
            : abi.encode(bytes1(0x0f), type(uint256).max, uint256(0), uint256(0), address(0), bytes32(0), uint256(0));
        assembly ("memory-safe") {
            return(add(answer, 0x20), mload(answer))
        }
    }

}
