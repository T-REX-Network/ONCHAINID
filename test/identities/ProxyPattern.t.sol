// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { IdentityHelper } from "../helpers/IdentityHelper.sol";
import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Test } from "forge-std/Test.sol";

contract ProxyPatternTest is Test {

    address internal deployer;
    address internal alice;

    function setUp() public {
        deployer = makeAddr("proxyDeployer");
        alice = makeAddr("proxyAlice");
    }

    function test_deployIdentityThroughProxyAndWorkCorrectly() public {
        vm.prank(deployer);
        (Identity identityProxy,) = IdentityHelper.deployIdentityWithProxy(deployer);

        assertEq(identityProxy.version(), "3.0.0");

        bytes32 deployerKey = ClaimSignerHelper.addressToKey(deployer);
        assertTrue(IERC734(address(identityProxy)).keyHasPurpose(deployerKey, KeyPurposes.MANAGEMENT));

        bytes32 aliceKey = ClaimSignerHelper.addressToKey(alice);
        vm.prank(deployer);
        identityProxy.addKeyWithData(aliceKey, KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(alice), "");

        assertTrue(IERC734(address(identityProxy)).keyHasPurpose(aliceKey, KeyPurposes.ACTION));
    }

}
