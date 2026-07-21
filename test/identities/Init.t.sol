// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

contract InitTest is OnchainIDSetup {

    function test_revert_whenReinitializingDeployedIdentity() public {
        vm.prank(alice);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        aliceIdentity.initialize(IdentityTypes.INDIVIDUAL, new Structs.KeyParam[](0), new Structs.ModuleInstall[](0));
    }

    function test_revert_whenInitializingLibraryDirectly() public {
        // Every implementation locks its own `Initializable` slot in the constructor, so any
        // call to `initialize` on it (rather than on a proxy) reverts.
        Identity libraryImpl = new Identity(address(onchainidSetup.signatureValidator));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        libraryImpl.initialize(IdentityTypes.INDIVIDUAL, new Structs.KeyParam[](0), new Structs.ModuleInstall[](0));
    }

    function test_versionInitializedWhenDeployedAsRegularContract() public {
        Identity identityImplementation = getIdentityImplementation();
        assertEq(identityImplementation.version(), "3.0.0");
    }

    function test_revert_whenCallingLibraryImplementationDirectly() public {
        Identity libraryImpl = new Identity(address(onchainidSetup.signatureValidator));

        // The implementation's registry (keyed by its own address in the validator) holds no
        // keys, so nobody passes the MANAGEMENT gate on the write entry points.
        vm.prank(deployer);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        libraryImpl.addKey(keccak256(abi.encodePacked(alice)), 1, 1);
    }

    function test_accountId_returnsExpectedValue() public view {
        assertEq(aliceIdentity.accountId(), "trex.onchainid.identity.v3.0.0");
    }

    function test_supportsERC165InterfaceDetection() public {
        // ERC165 interface ID
        assertTrue(aliceIdentity.supportsInterface(0x01ffc9a7));

        // Invalid interface IDs
        assertFalse(aliceIdentity.supportsInterface(0x12345678));
        assertFalse(aliceIdentity.supportsInterface(0x00000000));
        assertFalse(aliceIdentity.supportsInterface(0xffffffff));
    }

}
