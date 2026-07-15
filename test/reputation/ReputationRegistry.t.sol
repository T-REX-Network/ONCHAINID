// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { IReputationRegistry } from "contracts/reputation/IReputationRegistry.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";

/// @title ReputationRegistry tests
/// @dev The registry is deployed fresh per test against the OnchainIDSetup
///      AccessManager and factory so every assertion has clean state.
///      `REPUTATION_MANAGER_ROLE` is a fresh role created in setUp and granted
///      to `reputationManager`. Tests can grant it to other addresses to
///      exercise the auth path.
contract ReputationRegistryTest is OnchainIDSetup {

    ReputationRegistry internal registry;

    uint64 internal constant REPUTATION_MANAGER_ROLE = 1001;

    address internal reputationManager;

    // Two arbitrary scores used across the tests. The registry treats these as
    // opaque numbers; only the ordering matters.
    uint128 internal constant LOW_SCORE = 10;
    uint128 internal constant HIGH_SCORE = 50;

    function setUp() public override {
        super.setUp();
        reputationManager = makeAddr("reputationManager");

        registry = new ReputationRegistry(address(onchainidSetup.accessManager), address(onchainidSetup.idFactory));

        // Restrict the three restricted setters to REPUTATION_MANAGER_ROLE and grant
        // the role to `reputationManager`.
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = ReputationRegistry.setReputation.selector;
        selectors[1] = ReputationRegistry.setDefault.selector;
        selectors[2] = ReputationRegistry.setClaimAddThreshold.selector;

        vm.startPrank(deployer);
        onchainidSetup.accessManager.setTargetFunctionRole(address(registry), selectors, REPUTATION_MANAGER_ROLE);
        onchainidSetup.accessManager.grantRole(REPUTATION_MANAGER_ROLE, reputationManager, 0);
        vm.stopPrank();
    }

    // ============ Constructor ============

    function test_constructor_revertOnZeroAuthority() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new ReputationRegistry(address(0), address(onchainidSetup.idFactory));
    }

    function test_constructor_revertOnZeroFactory() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new ReputationRegistry(address(onchainidSetup.accessManager), address(0));
    }

    function test_constructor_storesFactory() public view {
        assertEq(address(registry.factory()), address(onchainidSetup.idFactory));
    }

    // ============ setDefault ============

    function test_setDefault_revertWhenCallerLacksRole() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessManagerUnauthorizedAccount
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE);
    }

    function test_setDefault_managerCanSet() public {
        vm.prank(reputationManager);
        vm.expectEmit(true, false, false, true, address(registry));
        emit IReputationRegistry.DefaultSet(IdentityTypes.CLAIM_ISSUER, 0, HIGH_SCORE);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE);

        assertEq(registry.defaultFor(IdentityTypes.CLAIM_ISSUER), HIGH_SCORE);
    }

    function test_setDefault_overwritesAndEmitsOld() public {
        vm.startPrank(reputationManager);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IReputationRegistry.DefaultSet(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE, 99);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, 99);
        vm.stopPrank();
    }

    // ============ setClaimAddThreshold ============

    function test_setClaimAddThreshold_revertWhenCallerLacksRole() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessManagerUnauthorizedAccount
        registry.setClaimAddThreshold(HIGH_SCORE);
    }

    function test_setClaimAddThreshold_managerCanSet() public {
        vm.prank(reputationManager);
        vm.expectEmit(false, false, false, true, address(registry));
        emit IReputationRegistry.ClaimAddThresholdSet(0, HIGH_SCORE);
        registry.setClaimAddThreshold(HIGH_SCORE);

        assertEq(registry.claimAddThreshold(), HIGH_SCORE);
    }

    function test_setClaimAddThreshold_overwritesAndEmitsOld() public {
        vm.startPrank(reputationManager);
        registry.setClaimAddThreshold(HIGH_SCORE);

        vm.expectEmit(false, false, false, true, address(registry));
        emit IReputationRegistry.ClaimAddThresholdSet(HIGH_SCORE, 99);
        registry.setClaimAddThreshold(99);
        vm.stopPrank();
    }

    // ============ setReputation ============

    function test_setReputation_revertWhenCallerLacksRole() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessManagerUnauthorizedAccount
        registry.setReputation(address(aliceIdentity), HIGH_SCORE);
    }

    function test_setReputation_revertOnZeroIdentity() public {
        vm.prank(reputationManager);
        vm.expectRevert(Errors.ZeroAddress.selector);
        registry.setReputation(address(0), HIGH_SCORE);
    }

    function test_setReputation_managerCanSet() public {
        vm.prank(reputationManager);
        vm.expectEmit(true, false, false, true, address(registry));
        emit IReputationRegistry.ReputationSet(address(aliceIdentity), 0, HIGH_SCORE, reputationManager);
        registry.setReputation(address(aliceIdentity), HIGH_SCORE);

        assertEq(registry.reputationOf(address(aliceIdentity)), HIGH_SCORE);

        (uint128 score, uint128 setAt) = registry.entryOf(address(aliceIdentity));
        assertEq(score, HIGH_SCORE);
        assertEq(setAt, uint128(block.timestamp));
    }

    function test_setReputation_explicitZeroIsDistinctFromUnset() public {
        // Set a non-zero default so the lazy fallback would otherwise return it.
        vm.prank(reputationManager);
        registry.setDefault(IdentityTypes.INDIVIDUAL, LOW_SCORE);

        // alice is a factory identity of type INDIVIDUAL. Before any explicit
        // entry, reputationOf falls back to the default.
        assertEq(registry.reputationOf(address(aliceIdentity)), LOW_SCORE);

        // Manager explicitly sets her to 0, which should win over the default.
        vm.prank(reputationManager);
        registry.setReputation(address(aliceIdentity), 0);
        assertEq(registry.reputationOf(address(aliceIdentity)), 0);

        // entryOf still reports a real entry (score 0 at a non-zero timestamp),
        // distinguishing "manager set to 0" from "never written".
        (uint128 score, uint128 setAt) = registry.entryOf(address(aliceIdentity));
        assertEq(score, 0);
        assertTrue(setAt != 0);
    }

    function test_setReputation_overwritesExistingScore() public {
        vm.startPrank(reputationManager);
        registry.setReputation(address(aliceIdentity), LOW_SCORE);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IReputationRegistry.ReputationSet(address(aliceIdentity), LOW_SCORE, HIGH_SCORE, reputationManager);
        registry.setReputation(address(aliceIdentity), HIGH_SCORE);
        vm.stopPrank();

        assertEq(registry.reputationOf(address(aliceIdentity)), HIGH_SCORE);
    }

    // ============ reputationOf lazy fallback ============

    function test_reputationOf_returnsDefaultForFactoryIdentity() public {
        // alice is factory-deployed as INDIVIDUAL. Configure a non-zero default
        // for that type and confirm reputationOf returns it.
        vm.prank(reputationManager);
        registry.setDefault(IdentityTypes.INDIVIDUAL, LOW_SCORE);

        assertEq(registry.reputationOf(address(aliceIdentity)), LOW_SCORE);
    }

    function test_reputationOf_returnsZeroForNonFactoryAddress() public {
        // Any address that the factory did not deploy reads 0, even when a
        // non-zero default has been set for whatever type it might advertise.
        vm.prank(reputationManager);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE);

        address randomAddress = makeAddr("notFromFactory");
        assertEq(registry.reputationOf(randomAddress), 0);
    }

    function test_reputationOf_returnsZeroForFakeIdentityClaimingClaimIssuerType() public {
        // A contract that returns CLAIM_ISSUER from getIdentityType() but was
        // never deployed by the factory must still read 0. This is the bypass
        // the factory gate prevents.
        vm.prank(reputationManager);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, HIGH_SCORE);

        FakeIdentity fake = new FakeIdentity(IdentityTypes.CLAIM_ISSUER);
        assertEq(registry.reputationOf(address(fake)), 0);
    }

    function test_reputationOf_explicitEntryBypassesFactoryGate() public {
        // The factory gate only applies to the lazy fallback. An explicit entry
        // written by the manager is honored even for an address the factory did
        // not deploy, because the manager may want to score external identities
        // by hand.
        FakeIdentity fake = new FakeIdentity(IdentityTypes.CLAIM_ISSUER);

        vm.prank(reputationManager);
        registry.setReputation(address(fake), HIGH_SCORE);

        assertEq(registry.reputationOf(address(fake)), HIGH_SCORE);
    }

    function test_reputationOf_returnsZeroWhenTypeHasNoDefault() public view {
        // alice is factory-deployed (INDIVIDUAL) but no default has been set
        // for that type, so reputationOf returns 0 (the default of an unset
        // type is 0).
        assertEq(registry.reputationOf(address(aliceIdentity)), 0);
    }

    // ============ entryOf ============

    function test_entryOf_unsetReturnsZeroSetAt() public view {
        (uint128 score, uint128 setAt) = registry.entryOf(address(aliceIdentity));
        assertEq(score, 0);
        assertEq(setAt, 0);
    }

}

/// @dev A minimal contract that pretends to be a factory identity by returning
///      a configurable type from {getIdentityType}. The factory never deployed
///      it, so the registry's lazy fallback must reject it.
contract FakeIdentity {

    uint256 public immutable advertisedType;

    constructor(uint256 _type) {
        advertisedType = _type;
    }

    function getIdentityType() external view returns (uint256) {
        return advertisedType;
    }

}
