// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { ShiftedDomainIdentity } from "../mocks/ShiftedDomainIdentity.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";

/// @notice Coverage for ERC-735 claim management on an Identity (add, remove, get, isClaimValid).
contract ClaimsTest is OnchainIDSetup {

    /// @notice M-07 regression: removeClaim must revoke the digest saved when the claim was
    ///         added, not one recomputed from the issuer's live EIP-712 domain. Otherwise a
    ///         domain change on upgrade leaves the signed digest unrevoked.
    function test_removeClaim_revokesSignedDigest_afterDomainChange() public {
        bytes32 signedDigest = IIdentity(address(claimIssuer))
            .getClaimHash(address(aliceIdentity), aliceClaim666.topic, aliceClaim666.data);

        // Point the beacon at an implementation reporting a different domain version.
        ShiftedDomainIdentity newImpl =
            new ShiftedDomainIdentity(address(onchainidSetup.signatureValidator), address(onchainidSetup.idFactory));
        vm.prank(deployer);
        onchainidSetup.idFactory.upgradeBeacon(address(newImpl));

        vm.prank(carol);
        IIdentity(address(aliceIdentity)).removeClaim(aliceClaim666.id);

        assertTrue(
            IClaimIssuer(address(claimIssuer)).isDigestRevoked(signedDigest),
            "revocation must key the digest the issuer signed"
        );
    }

}
