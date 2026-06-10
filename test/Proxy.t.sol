// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";

import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";

import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";
import { Test as TestContract } from "./mocks/Test.sol";

contract ProxyTest is OnchainIDSetup {

    function _initData(address mgmtKey, uint256 idType) internal pure returns (bytes memory) {
        return abi.encodeCall(Identity.initialize, (mgmtKey, idType));
    }

    function test_revertBecauseBeaconIsZeroAddress() public {
        vm.expectRevert(abi.encode(ERC1967Utils.ERC1967InvalidBeacon.selector, address(0)));
        new BeaconProxy(address(0), _initData(alice, IdentityTypes.INDIVIDUAL));
    }

    function test_revertBecauseImplementationIsNotIdentity() public {
        TestContract testContract = new TestContract();
        UpgradeableBeacon b = new UpgradeableBeacon(address(testContract), address(this));

        vm.expectRevert(OZErrors.FailedCall.selector);
        new BeaconProxy(address(b), _initData(alice, IdentityTypes.INDIVIDUAL));
    }

    function test_revertBecauseInitialKeyIsZeroAddress() public {
        Identity impl = new Identity(deployer, true);
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), address(this));

        vm.expectRevert(Errors.ZeroAddress.selector);
        new BeaconProxy(address(b), _initData(address(0), IdentityTypes.INDIVIDUAL));
    }

    function test_preventCreatingBeaconWithZeroImplementation() public {
        vm.expectRevert(abi.encode(UpgradeableBeacon.BeaconInvalidImplementation.selector, address(0)));
        new UpgradeableBeacon(address(0), address(this));
    }

    function test_preventUpdatingToZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encode(UpgradeableBeacon.BeaconInvalidImplementation.selector, address(0)));
        onchainidSetup.beacon.upgradeTo(address(0));
    }

    function test_preventUpdatingWhenNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        onchainidSetup.beacon.upgradeTo(address(0));
    }

    function test_beacon_shouldReturnCorrectAddress() public {
        Identity impl = new Identity(deployer, false);
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), address(this));
        BeaconProxy proxy = new BeaconProxy(address(b), _initData(deployer, IdentityTypes.INDIVIDUAL));

        // ERC-1967 beacon slot: bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
        bytes32 beaconSlot = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
        address storedBeacon = address(uint160(uint256(vm.load(address(proxy), beaconSlot))));
        assertEq(storedBeacon, address(b));
    }

    function test_updateImplementationAddress() public {
        Identity impl = new Identity(deployer, false);
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), address(this));
        new BeaconProxy(address(b), _initData(deployer, IdentityTypes.INDIVIDUAL));

        vm.expectEmit(true, true, true, true);
        emit UpgradeableBeacon.Upgraded(address(impl));
        b.upgradeTo(address(impl));
    }

}
