// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";

import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
import { IdentityProxy } from "contracts/proxy/IdentityProxy.sol";
import { ImplementationAuthority } from "contracts/proxy/ImplementationAuthority.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";
import { Test as TestContract } from "./mocks/Test.sol";

contract ProxyTest is OnchainIDSetup {

    function _mgmtKeys(address k) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(k)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(k),
            clientData: ""
        });
    }

    function _emptyModules() internal pure returns (Structs.ModuleInstall[] memory) {
        return new Structs.ModuleInstall[](0);
    }

    /// @dev Identity.initialize requires at least one validator or executor module. Tests that
    ///      bypass the factory (deploying IdentityProxy directly) need to supply one to pass init.
    function _modulesWithValidator() internal returns (Structs.ModuleInstall[] memory modules) {
        modules = new Structs.ModuleInstall[](1);
        modules[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(new ERC7579Signature()), initData: "", purpose: 0
        });
    }

    function test_revertBecauseImplementationIsZeroAddress() public {
        vm.expectRevert(abi.encode(ERC1967Utils.ERC1967InvalidBeacon.selector, address(0)));
        new IdentityProxy(address(0), IdentityTypes.INDIVIDUAL, _mgmtKeys(alice), _emptyModules());
    }

    function test_revertBecauseImplementationIsNotIdentity() public {
        TestContract testContract = new TestContract();
        ImplementationAuthority authority = new ImplementationAuthority(address(testContract), address(this));

        vm.expectRevert(OZErrors.FailedCall.selector);
        new IdentityProxy(address(authority), IdentityTypes.INDIVIDUAL, _mgmtKeys(alice), _emptyModules());
    }

    /// @notice Initializing with an empty keys array reverts because the post-loop invariant
    ///         requires at least one MANAGEMENT key. Replaces the old zero-address initial-key check.
    function test_revertBecauseNoManagementKeyProvided() public {
        Identity impl = new Identity(true);
        ImplementationAuthority authority = new ImplementationAuthority(address(impl), address(this));

        vm.expectRevert(Errors.NoManagementKeyInKeys.selector);
        new IdentityProxy(address(authority), IdentityTypes.INDIVIDUAL, new Structs.KeyParam[](0), _emptyModules());
    }

    function test_preventCreatingAuthorityWithZeroAddress() public {
        vm.expectRevert(abi.encode(UpgradeableBeacon.BeaconInvalidImplementation.selector, address(0)));
        new ImplementationAuthority(address(0), address(this));
    }

    function test_preventUpdatingToZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encode(UpgradeableBeacon.BeaconInvalidImplementation.selector, address(0)));
        onchainidSetup.implementationAuthority.upgradeTo(address(0));
    }

    function test_preventUpdatingWhenNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        onchainidSetup.implementationAuthority.upgradeTo(address(0));
    }

    function test_implementationAuthority_shouldReturnCorrectAddress() public {
        Identity impl = new Identity(true);
        ImplementationAuthority authority = new ImplementationAuthority(address(impl), address(this));
        IdentityProxy proxy = new IdentityProxy(
            address(authority), IdentityTypes.INDIVIDUAL, _mgmtKeys(deployer), _modulesWithValidator()
        );

        // ERC-1967 beacon slot: bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)
        bytes32 beaconSlot = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
        address storedBeacon = address(uint160(uint256(vm.load(address(proxy), beaconSlot))));
        assertEq(storedBeacon, address(authority), "Should store the correct authority address as beacon");
    }

    function test_updateImplementationAddress() public {
        // Deploy identity with its own proxy and authority
        Identity impl = new Identity(true);
        ImplementationAuthority authority = new ImplementationAuthority(address(impl), address(this));
        new IdentityProxy(address(authority), IdentityTypes.INDIVIDUAL, _mgmtKeys(deployer), _modulesWithValidator());

        vm.expectEmit(true, true, true, true);
        emit UpgradeableBeacon.Upgraded(address(impl));
        authority.upgradeTo(address(impl));
    }

}
