// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";

/// @notice Coverage for ERC-735 claim management on an Identity (add, remove, get, isClaimValid).
contract ClaimsTest is OnchainIDSetup {

    /// @notice ClaimAdded carries the subject identity. The claims module is a singleton and
    ///         claimId is derived from (issuer, topic) only, so without the subject field the
    ///         same claim on two identities produces byte-identical logs from the same emitter.
    function test_addClaim_emitsClaimAdded_withSubjectIdentity() public {
        // Same issuer and topic as alice's fixture claim -> same claimId. Only the identity
        // field distinguishes bob's log from alice's.
        ClaimSignerHelper.Claim memory bobClaim = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(bobIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_666,
            hex"0042",
            "https://example.com"
        );
        assertEq(bobClaim.id, aliceClaim666.id, "same (issuer, topic) => same claimId across identities");

        vm.expectEmit(true, true, true, true);
        emit IERC735.ClaimAdded(
            address(bobIdentity),
            bobClaim.id,
            bobClaim.topic,
            bobClaim.scheme,
            bobClaim.issuer,
            bobClaim.signature,
            bobClaim.data,
            bobClaim.uri
        );
        vm.prank(bob);
        IIdentity(address(bobIdentity))
            .addClaim(bobClaim.topic, bobClaim.scheme, bobClaim.issuer, bobClaim.signature, bobClaim.data, bobClaim.uri);
    }

    /// @notice Re-adding an existing claimId emits ClaimChanged, also carrying the subject.
    function test_addClaim_existingClaimId_emitsClaimChanged_withSubjectIdentity() public {
        ClaimSignerHelper.Claim memory updated = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(aliceIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_666,
            hex"1337",
            "https://example.com/v2"
        );

        vm.expectEmit(true, true, true, true);
        emit IERC735.ClaimChanged(
            address(aliceIdentity),
            updated.id,
            updated.topic,
            updated.scheme,
            updated.issuer,
            updated.signature,
            updated.data,
            updated.uri
        );
        vm.prank(alice);
        IIdentity(address(aliceIdentity))
            .addClaim(updated.topic, updated.scheme, updated.issuer, updated.signature, updated.data, updated.uri);
    }

    /// @notice ClaimRemoved carries the subject identity as well.
    function test_removeClaim_emitsClaimRemoved_withSubjectIdentity() public {
        vm.expectEmit(true, true, true, true);
        emit IERC735.ClaimRemoved(
            address(aliceIdentity),
            aliceClaim666.id,
            aliceClaim666.topic,
            aliceClaim666.scheme,
            aliceClaim666.issuer,
            aliceClaim666.signature,
            aliceClaim666.data,
            aliceClaim666.uri
        );
        vm.prank(alice);
        IIdentity(address(aliceIdentity)).removeClaim(aliceClaim666.id);
    }

}
