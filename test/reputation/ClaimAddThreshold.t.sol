// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Identity } from "contracts/Identity.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice A threshold of zero accepts every score. Claim adds fail closed until a
///         positive threshold is set and the issuer's score meets it. Raising the
///         threshold later does not remove a claim that was already stored.
contract ClaimAddThresholdTest is OnchainIDSetup {

    uint256 internal constant ALICE_TOPIC = 11_001;
    uint256 internal constant BOB_TOPIC = 11_002;

    function test_zeroThresholdRejectsClaimAddsUntilAPositiveScoreMeetsIt() public {
        ReputationRegistry registry = onchainidSetup.reputationRegistry;

        assertEq(registry.claimAddThreshold(), 0);
        assertEq(registry.defaultFor(IdentityTypes.CLAIM_ISSUER), 0);
        (uint128 score, uint128 setAt) = registry.entryOf(address(claimIssuer));
        assertEq(score, 0);
        assertEq(setAt, 0);
        assertEq(registry.reputationOf(address(claimIssuer)), 0);
        assertEq(onchainidSetup.idFactory.identityTypeOf(address(claimIssuer)), IdentityTypes.CLAIM_ISSUER);
        assertFalse(_holderHasClaimKey(address(aliceIdentity), address(claimIssuer)));
        assertFalse(_holderHasClaimKey(address(bobIdentity), address(claimIssuer)));

        (bytes memory aliceSignature, Structs.ClaimData memory aliceData) = _signed(address(aliceIdentity), ALICE_TOPIC);
        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.ZeroClaimAddThreshold.selector);
        ERC734Validator(address(aliceIdentity))
            .addClaim(ALICE_TOPIC, 1, address(claimIssuer), aliceSignature, aliceData, "");
        _assertAbsent(address(aliceIdentity), ALICE_TOPIC);

        (bytes memory bobSignature, Structs.ClaimData memory bobData) = _signed(address(bobIdentity), BOB_TOPIC);
        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.ZeroClaimAddThreshold.selector);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(BOB_TOPIC, 1, bobSignature, bobData, "", IIdentity(address(bobIdentity)));
        _assertAbsent(address(bobIdentity), BOB_TOPIC);

        // Deployer holds the admin role, which is what an untouched setter uses.
        vm.prank(deployer);
        registry.setClaimAddThreshold(1);

        vm.prank(address(claimIssuer));
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, 1)
        );
        ERC734Validator(address(aliceIdentity))
            .addClaim(ALICE_TOPIC, 1, address(claimIssuer), aliceSignature, aliceData, "");
        _assertAbsent(address(aliceIdentity), ALICE_TOPIC);

        vm.prank(deployer);
        registry.setReputation(address(claimIssuer), 1);

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity))
            .addClaim(ALICE_TOPIC, 1, address(claimIssuer), aliceSignature, aliceData, "");
        _assertStored(address(aliceIdentity), ALICE_TOPIC);

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(BOB_TOPIC, 1, bobSignature, bobData, "", IIdentity(address(bobIdentity)));
        _assertStored(address(bobIdentity), BOB_TOPIC);

        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroClaimAddThreshold.selector);
        registry.setClaimAddThreshold(0);
        assertEq(registry.claimAddThreshold(), 1);

        vm.prank(deployer);
        registry.setClaimAddThreshold(2);
        _assertStored(address(aliceIdentity), ALICE_TOPIC);
        _assertStored(address(bobIdentity), BOB_TOPIC);
    }

    function _signed(address holder, uint256 topic)
        internal
        view
        returns (bytes memory signature, Structs.ClaimData memory data)
    {
        data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: ClaimSignerHelper.metadataHash(1, ""),
            payload: hex"01"
        });
        signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(claimIssuer), holder, topic, data
        );
    }

    function _holderHasClaimKey(address holder, address caller) internal view returns (bool) {
        bytes32 key = ClaimSignerHelper.addressToKey(caller);
        Identity id = Identity(payable(holder));
        return id.keyHasPurpose(key, KeyPurposes.CLAIM_SIGNER) || id.keyHasPurpose(key, KeyPurposes.CLAIM_ADDER)
            || id.keyHasPurpose(key, KeyPurposes.MANAGEMENT);
    }

    function _assertStored(address holder, uint256 topic) internal view {
        (uint256 found,, address issuer,,,) =
            IIdentity(holder).getClaim(ClaimSignerHelper.computeClaimId(address(claimIssuer), topic));
        assertEq(found, topic);
        assertEq(issuer, address(claimIssuer));
    }

    function _assertAbsent(address holder, uint256 topic) internal view {
        (uint256 found,, address issuer,,,) =
            IIdentity(holder).getClaim(ClaimSignerHelper.computeClaimId(address(claimIssuer), topic));
        assertEq(found, 0);
        assertEq(issuer, address(0));
    }

}
