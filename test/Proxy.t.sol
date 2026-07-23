// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { MODULE_TYPE_FALLBACK, MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";

import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";
import { Test as TestContract } from "./mocks/Test.sol";

contract ProxyTest is OnchainIDSetup {

    /// @dev Build a minimal initialize() calldata. One MANAGEMENT key plus a validator
    ///      module so Identity.initialize's shape invariants pass.
    function _initData(uint256 idType) internal view returns (bytes memory) {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        bytes memory signer = abi.encodePacked(alice);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(signer),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: signer,
            clientData: ""
        });

        address validator = address(onchainidSetup.signatureValidator);
        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](5);
        // Empty initData: the MANAGEMENT key is seeded from `keys` above, so seeding it again in
        // the validator's onInstall would collide (KeyAlreadyRegistered).
        modules[0] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_VALIDATOR, module: validator, initData: "", purpose: 0 });
        modules[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: validator,
            initData: abi.encodePacked(IERC734.keyHasPurpose.selector),
            purpose: 0
        });
        modules[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: validator,
            initData: abi.encodePacked(IERC734.getKey.selector),
            purpose: 0
        });
        modules[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: validator,
            initData: abi.encodePacked(IERC734.getKeyPurposes.selector),
            purpose: 0
        });
        modules[4] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: validator,
            initData: abi.encodePacked(IERC734.getKeysByPurpose.selector),
            purpose: 0
        });

        return abi.encodeCall(Identity.initialize, (idType, keys, modules));
    }

    function test_revertBecauseBeaconIsZeroAddress() public {
        vm.expectRevert(abi.encode(ERC1967Utils.ERC1967InvalidBeacon.selector, address(0)));
        new BeaconProxy(address(0), _initData(IdentityTypes.INDIVIDUAL));
    }

    function test_revertBecauseImplementationIsNotIdentity() public {
        TestContract testContract = new TestContract();
        UpgradeableBeacon b = new UpgradeableBeacon(address(testContract), address(this));

        vm.expectRevert(OZErrors.FailedCall.selector);
        new BeaconProxy(address(b), _initData(IdentityTypes.INDIVIDUAL));
    }

    function test_preventCreatingBeaconWithZeroImplementation() public {
        vm.expectRevert(abi.encode(UpgradeableBeacon.BeaconInvalidImplementation.selector, address(0)));
        new UpgradeableBeacon(address(0), address(this));
    }

    function test_preventUpdatingToZeroAddress() public {
        // The factory owns the beacon, so upgrades go through factory.upgradeBeacon; a zero
        // implementation is rejected by the factory before it reaches the beacon.
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.upgradeBeacon(address(0));
    }

    function test_preventUpdatingWhenNotOwner() public {
        // Only the factory owns the beacon, so a direct upgradeTo by anyone else reverts.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        onchainidSetup.beacon.upgradeTo(address(0));
    }

    function test_beacon_shouldReturnCorrectAddress() public {
        Identity impl = new Identity(address(onchainidSetup.signatureValidator));
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), address(this));
        BeaconProxy proxy = new BeaconProxy(address(b), _initData(IdentityTypes.INDIVIDUAL));

        // ERC-1967 beacon slot: bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
        bytes32 beaconSlot = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
        address storedBeacon = address(uint160(uint256(vm.load(address(proxy), beaconSlot))));
        assertEq(storedBeacon, address(b));
    }

    function test_updateImplementationAddress() public {
        Identity impl = new Identity(address(onchainidSetup.signatureValidator));
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), address(this));
        new BeaconProxy(address(b), _initData(IdentityTypes.INDIVIDUAL));

        vm.expectEmit(true, true, true, true);
        emit UpgradeableBeacon.Upgraded(address(impl));
        b.upgradeTo(address(impl));
    }

}
