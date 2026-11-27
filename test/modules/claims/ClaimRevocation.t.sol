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
        assertEq(uint256(_aliceClaim666Status()), uint256(IClaimIssuer.ClaimStatus.Revoked));
    }

    function test_removeClaim_RevertWhen_TheRemovedClaimIsAddedAgain() public {
        vm.startPrank(alice);
        IIdentity(address(aliceIdentity)).removeClaim(aliceClaim666.id);

        vm.expectRevert(Errors.InvalidClaim.selector);
        IIdentity(address(aliceIdentity))
            .addClaim(
                aliceClaim666.topic,
                aliceClaim666.scheme,
                aliceClaim666.issuer,
                aliceClaim666.signature,
                aliceClaim666.data,
                aliceClaim666.uri
            );
        vm.stopPrank();
    }

    function test_revokeClaimByDigest_withTheStructHash_revokesTheClaim() public {
        bytes32 claimStructHash =
            ClaimSignerHelper.claimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);
        assertEq(uint256(_aliceClaim666Status()), uint256(IClaimIssuer.ClaimStatus.Valid));

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimByDigest(claimStructHash);

        assertEq(uint256(_aliceClaim666Status()), uint256(IClaimIssuer.ClaimStatus.Revoked));
    }

    function test_getClaimStructHash_isTheValueRevocationsAreKeyedOn() public {
        bytes32 claimStructHash = onchainidSetup.signatureValidator
            .getClaimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);
        assertEq(
            claimStructHash,
            ClaimSignerHelper.claimStructHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data)
        );

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimByDigest(claimStructHash);

        assertEq(uint256(_aliceClaim666Status()), uint256(IClaimIssuer.ClaimStatus.Revoked));
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

    /// @dev The module reads the issuer from `msg.sender`, and identities have no fallback for
    ///      `getClaimStatus`, so call the singleton as the issuer identity.
    function _aliceClaim666Status() internal returns (IClaimIssuer.ClaimStatus) {
        vm.prank(address(claimIssuer));
        return onchainidSetup.signatureValidator
            .getClaimStatus(
                IIdentity(address(aliceIdentity)), aliceClaim666.topic, aliceClaim666.signature, aliceClaim666.data
            );
    }

}
