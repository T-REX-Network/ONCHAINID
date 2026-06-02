// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";

contract InitTest is OnchainIDSetup {

    function test_revert_whenReinitializingDeployedIdentity() public {
        vm.prank(alice);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        aliceIdentity.initialize(alice, IdentityTypes.INDIVIDUAL);
    }

    function test_revert_whenInitializingWithZeroAddress() public {
        // The library implementation is constructed with `_disableInitializers()`, so any
        // call to `initialize` on it reverts via OZ's `Initializable` slot — before the
        // zero-address check even runs.
        Identity libraryImpl = new Identity(deployer, true);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        libraryImpl.initialize(address(0), IdentityTypes.INDIVIDUAL);
    }

    function test_revert_whenCreatingIdentityWithInvalidInitialKey() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new Identity(address(0), false);
    }

    function test_versionInitializedWhenDeployedAsRegularContract() public {
        Identity identityImplementation = getIdentityImplementation();
        assertEq(identityImplementation.version(), "3.0.0");
    }

    function test_revert_whenInitializingLibraryWithValidAddress() public {
        // Library implementations are locked at construction time via `_disableInitializers()`,
        // so `initialize` reverts with OZ's standard `InvalidInitialization` regardless of args.
        Identity libraryImpl = new Identity(deployer, true);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        libraryImpl.initialize(deployer, IdentityTypes.INDIVIDUAL);
    }

    function test_revert_whenCallingLibraryImplementationDirectly() public {
        Identity libraryImpl = new Identity(deployer, true);

        vm.prank(deployer);
        vm.expectRevert(Errors.InteractingWithLibraryContractForbidden.selector);
        libraryImpl.addKey(keccak256(abi.encodePacked(alice)), 1, 1);
    }

    function test_accountId_returnsExpectedValue() public view {
        assertEq(aliceIdentity.accountId(), "trex.onchainid.identity.v3.0.0");
    }

    /// @notice ERC-7201 namespaced slots: KeyManager and Identity metadata don't alias.
    function test_storage_namespacedSlotsDoNotCollide() public view {
        // The metadata slot holds the identityType (=2 for INDIVIDUAL).
        bytes32 metaSlot = keccak256(abi.encode(uint256(keccak256(bytes("onchainid.identity.metadata"))) - 1))
            & ~bytes32(uint256(0xff));
        bytes32 keysSlot = keccak256(abi.encode(uint256(keccak256(bytes("onchainid.keymanager.storage"))) - 1))
            & ~bytes32(uint256(0xff));
        assertTrue(metaSlot != keysSlot, "namespaced slots must differ");
        // identityType at meta slot should equal 2 (INDIVIDUAL).
        bytes32 raw = vm.load(address(aliceIdentity), metaSlot);
        assertEq(uint256(raw), IdentityTypes.INDIVIDUAL);
    }

    /// @notice Identity exposes the expected identity type from the metadata slot.
    function test_getIdentityType_returnsConfiguredType() public view {
        assertEq(aliceIdentity.getIdentityType(), IdentityTypes.INDIVIDUAL);
        assertEq(claimIssuer.getIdentityType(), IdentityTypes.CLAIM_ISSUER);
    }

}
