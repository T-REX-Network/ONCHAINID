// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
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
        Identity libraryImpl =
            new Identity(address(onchainidSetup.signatureValidator), address(onchainidSetup.idFactory));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        libraryImpl.initialize(IdentityTypes.INDIVIDUAL, new Structs.KeyParam[](0), new Structs.ModuleInstall[](0));
    }

    function test_versionInitializedWhenDeployedAsRegularContract() public {
        Identity identityImplementation = getIdentityImplementation();
        assertEq(identityImplementation.version(), "3.0.0");
    }

    function test_revert_whenCallingLibraryImplementationDirectly() public {
        Identity libraryImpl =
            new Identity(address(onchainidSetup.signatureValidator), address(onchainidSetup.idFactory));

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

    function test_supportsInterface_tracksInstalledFallbackSurface() public {
        assertTrue(aliceIdentity.supportsInterface(type(IERC734).interfaceId));
        assertTrue(aliceIdentity.supportsInterface(type(IERC735).interfaceId));
        assertTrue(aliceIdentity.supportsInterface(type(IIdentity).interfaceId));

        // Uninstalling the claim handler drops the claim interfaces; the registry stays.
        vm.prank(alice);
        aliceIdentity.uninstallModule(
            MODULE_TYPE_FALLBACK,
            address(onchainidSetup.signatureValidator),
            abi.encodePacked(IERC735.getClaim.selector)
        );

        // The key reads are enshrined functions on the account, not fallback handlers,
        // so the registry surface survives any uninstall and stays advertised.
        assertTrue(aliceIdentity.supportsInterface(type(IERC734).interfaceId));
        assertFalse(aliceIdentity.supportsInterface(type(IERC735).interfaceId));
        assertFalse(aliceIdentity.supportsInterface(type(IIdentity).interfaceId));
    }

    function test_supportsExecutionMode_matchesExecute() public view {
        // Mode layout: callType (1 byte) | execType (1 byte) | reserved.
        assertTrue(aliceIdentity.supportsExecutionMode(bytes32(0))); // single / default
        assertTrue(aliceIdentity.supportsExecutionMode(bytes32(uint256(0x01) << 248))); // batch / default
        assertTrue(aliceIdentity.supportsExecutionMode(bytes32(uint256(0x01) << 240))); // single / try
        assertFalse(aliceIdentity.supportsExecutionMode(bytes32(uint256(0xff) << 248))); // delegatecall
        assertFalse(aliceIdentity.supportsExecutionMode(bytes32(uint256(0x02) << 248))); // unknown call type
        assertFalse(aliceIdentity.supportsExecutionMode(bytes32(uint256(0x02) << 240))); // unknown exec type
    }

}
