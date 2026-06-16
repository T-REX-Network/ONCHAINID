// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (master, pending v5.7) (utils/Create3.sol)
//
// Vendored from openzeppelin-contracts master pending the v5.7 release.
// Source: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Create3.sol
// Origin PR: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/6402
pragma solidity ^0.8.20;

import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";
import { Errors } from "@openzeppelin/contracts/utils/Errors.sol";

import { LowLevelCall } from "./LowLevelCall.sol";

/**
 * @dev Helper to deploy contracts using the `CREATE3` approach.
 * `CREATE3` combines both `CREATE2` and `CREATE` opcodes to deploy arbitrary bytecode at an address that only depends
 * on the provided salt and the address of the contract using this library. At a high level, it behaves like a `CREATE2`
 * operation that would not use the bytecodehash to generate the contract address.
 *
 * CREATE3 can be used to compute in advance the address where a smart contract will be deployed, even if the bytecode
 * is subject to change.
 *
 * NOTE: To get the same deployment address on multiple chains, the deployer contract must live at the same address on
 * each chain.
 *
 * See {Create2} for counterfactual deployments that include the bytecodehash in the computation of the address.
 */
library Create3 {

    /// @dev The proxy initialization code.
    bytes28 private constant PROXY_INITCODE = 0x73365f5f37365f34f06012573d5f5f3e3d5ffd5b005f526014600cf3;

    /// @dev Hash of the `PROXY_INITCODE`.
    bytes32 internal constant PROXY_INITCODE_HASH = 0x57a34f6e879358dd76825d6700df87013ad6a3fb43c0d0c602f70a8772c153bd;

    error Create3EmptyBytecode();

    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address) {
        if (address(this).balance < amount) {
            revert Errors.InsufficientBalance(address(this).balance, amount);
        }
        if (bytecode.length == 0) {
            revert Create3EmptyBytecode();
        }

        address proxy = Create2.deploy(0, salt, abi.encodePacked(PROXY_INITCODE));
        bool success = LowLevelCall.callNoReturn(proxy, amount, bytecode);

        if (!success) {
            if (LowLevelCall.returnDataSize() == 0) {
                revert Errors.FailedDeployment();
            } else {
                LowLevelCall.bubbleRevert();
            }
        }

        return _computeCreateAddress(proxy);
    }

    function computeAddress(bytes32 salt) internal view returns (address) {
        return computeAddress(salt, address(this));
    }

    function computeAddress(bytes32 salt, address deployer) internal pure returns (address) {
        return _computeCreateAddress(Create2.computeAddress(salt, PROXY_INITCODE_HASH, deployer));
    }

    function _computeCreateAddress(address creator) private pure returns (address addr) {
        assembly ("memory-safe") {
            mstore(0x15, 0x01)
            mstore(0x14, creator)
            mstore(0x00, 0xd694)
            addr := and(keccak256(0x1e, 0x17), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

}
