// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";

/// @notice Revocations are keyed on the claim's EIP-712 struct hash in the issuer's own set.
///
///         In the fixture, `claimIssuerOwner` holds MANAGEMENT and CLAIM_SIGNER on `claimIssuer`,
///         and `aliceClaim666` is a claim from `claimIssuer` on `aliceIdentity`.
contract ClaimRevocationTest is OnchainIDSetup {

    function test_removeClaim_revokesTheClaimOnTheIssuer() public {
        bytes32 claimStructHash =
            ClaimSignerHelper.claimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);

        vm.prank(alice);
        IIdentity(address(aliceIdentity)).removeClaim(aliceClaim666.id);

        vm.prank(claimIssuerOwner);
        assertTrue(IClaimIssuer(address(claimIssuer)).isDigestRevoked(claimStructHash), "issuer must see it revoked");
        assertFalse(_aliceClaim666IsValid(), "the issuer must refuse the removed claim");
    }

    function test_revokeClaimByDigest_withTheStructHash_revokesTheClaim() public {
        bytes32 claimStructHash =
            ClaimSignerHelper.claimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);
        assertTrue(_aliceClaim666IsValid());

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimByDigest(claimStructHash);

        assertFalse(_aliceClaim666IsValid());
    }

    function test_revokeClaimByDigest_RevertWhen_TheClaimIsAlreadyRevoked() public {
        bytes32 claimStructHash =
            ClaimSignerHelper.claimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);

        vm.startPrank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimByDigest(claimStructHash);
        vm.expectRevert(Errors.ClaimAlreadyRevoked.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaimByDigest(claimStructHash);
        vm.stopPrank();
    }

    function _aliceClaim666IsValid() internal view returns (bool) {
        return IClaimIssuer(address(claimIssuer))
            .isClaimValid(
                IIdentity(address(aliceIdentity)), aliceClaim666.topic, aliceClaim666.signature, aliceClaim666.data
            );
    }

}
