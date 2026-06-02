// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";

import { Create3 } from "contracts/vendor/utils/Create3.sol";

import { Test } from "forge-std/Test.sol";

/// @notice Coverage shim for the vendored Create3 + LowLevelCall helpers. Real deployment
///         success paths are already exercised by IdFactory tests; this file focuses on the
///         negative branches (empty bytecode, deployment failure) and the address-computation
///         pure surface.
contract Create3Wrapper {

    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) external payable returns (address) {
        return Create3.deploy(amount, salt, bytecode);
    }

    function computeAddress(bytes32 salt) external view returns (address) {
        return Create3.computeAddress(salt);
    }

    function computeAddress(bytes32 salt, address deployer) external pure returns (address) {
        return Create3.computeAddress(salt, deployer);
    }

}

contract Create3Test is Test {

    Create3Wrapper internal _w;

    function setUp() public {
        _w = new Create3Wrapper();
    }

    /// @notice Empty bytecode triggers Create3EmptyBytecode.
    function test_deploy_emptyBytecode_reverts() public {
        vm.expectRevert(Create3.Create3EmptyBytecode.selector);
        _w.deploy(0, keccak256("salt"), "");
    }

    /// @notice amount > balance triggers InsufficientBalance.
    function test_deploy_insufficientBalance_reverts() public {
        bytes memory bytecode = hex"6080604052348015";
        vm.expectRevert(abi.encodeWithSelector(OZErrors.InsufficientBalance.selector, 0, 1));
        _w.deploy(1, keccak256("salt2"), bytecode);
    }

    /// @notice Deployment bytecode that reverts on construction surfaces FailedDeployment.
    function test_deploy_constructorRevert_bubblesOrFails() public {
        // Bytecode `60006000fd` = PUSH1 0; PUSH1 0; REVERT — empty-data revert at deploy.
        bytes memory bytecode = hex"60006000fd";
        // Either FailedDeployment (empty return data) or bubbled revert depending on solc.
        vm.expectRevert();
        _w.deploy(0, keccak256("salt3"), bytecode);
    }

    /// @notice Constructor revert WITH data must bubble the inner revert payload through
    ///         the CREATE3 proxy, exercising the `else` branch at Create3.sol:53
    ///         (`LowLevelCall.bubbleRevert()`) instead of the empty-data `FailedDeployment`
    ///         arm at line 51. Without this test the bubble arm is unreachable through
    ///         the public API.
    function test_deploy_constructorRevertsWithMessage_bubblesData() public {
        bytes memory initcode = type(ConstructorReverter).creationCode;
        // Solidity's `revert("BOOM")` encodes as Error(string) ABI — the proxy bubbles the
        // full payload, so we expect the encoded form, not the raw "BOOM" bytes.
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "BOOM"));
        _w.deploy(0, keccak256("bubble"), initcode);
    }

    /// @notice computeAddress(salt) is deterministic from `(address(this), salt)`.
    function test_computeAddress_oneArg_deterministic() public view {
        bytes32 salt = keccak256("ok");
        assertEq(_w.computeAddress(salt), _w.computeAddress(salt, address(_w)));
    }

    /// @notice computeAddress(salt, deployer) is pure — no contract state required.
    function test_computeAddress_twoArg_pure() public pure {
        address a = Create3.computeAddress(bytes32(uint256(1)), address(0x1234));
        address b = Create3.computeAddress(bytes32(uint256(1)), address(0x1234));
        assertEq(a, b);
    }

    /// @notice Same salt deployed twice → second reverts (proxy already deployed).
    function test_deploy_sameSaltTwice_reverts() public {
        // Minimal valid bytecode: STOP (0x00).
        bytes memory bytecode = hex"00";
        bytes32 salt = keccak256("dup");
        _w.deploy(0, salt, bytecode);
        vm.expectRevert();
        _w.deploy(0, salt, bytecode);
    }

}

/// @dev Constructor reverts with an Error(string) payload. Used to drive the bubble-revert
///      arm in Create3.deploy; its creationCode goes in as the `bytecode` argument.
contract ConstructorReverter {

    constructor() {
        revert("BOOM");
    }

}
