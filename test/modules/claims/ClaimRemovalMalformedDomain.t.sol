// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC735 } from "contracts/interface/IERC735.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { MockMalformedDomainIssuer } from "../../mocks/MockMalformedDomainIssuer.sol";

/// @notice Removing a claim reads the issuer's EIP-712 domain to revoke the claim's digest.
///         An issuer that answers with data that does not decode as a domain must not make its
///         claim unremovable. Such a claim is removed like one from an issuer with no domain at
///         all: nothing is revoked, and the claim leaves the identity.
///
///         In the fixture, `alice` holds MANAGEMENT on `aliceIdentity` and `carol` holds
///         CLAIM_SIGNER, so carol can add a claim from any issuer that accepts it.
contract ClaimRemovalMalformedDomainTest is OnchainIDSetup {

    uint256 internal constant TOPIC = 4242;

    MockMalformedDomainIssuer internal issuer;

    function setUp() public override {
        super.setUp();
        issuer = new MockMalformedDomainIssuer();
    }

    function test_claimFromIssuerWithTooShortDomain_canBeRemoved() public {
        issuer.setMode(MockMalformedDomainIssuer.Mode.TooShort);
        _addAndRemoveAsManagement();
    }

    function test_claimFromIssuerWithBadStringOffsetInDomain_canBeRemoved() public {
        issuer.setMode(MockMalformedDomainIssuer.Mode.BadStringOffset);
        _addAndRemoveAsManagement();
    }

    /// @notice The digest helper itself still reverts on a broken domain; only the removal path
    ///         turns that into "no digest".
    function test_claimDigestOf_revertsOnBrokenDomain() public {
        Structs.ClaimData memory data;
        vm.expectRevert();
        onchainidSetup.signatureValidator.claimDigestOf(address(issuer), address(aliceIdentity), TOPIC, data);
    }

    /// @dev carol adds a claim from `issuer`, then alice (MANAGEMENT) removes it.
    function _addAndRemoveAsManagement() internal {
        ERC734Validator claims = ERC734Validator(address(aliceIdentity));
        Structs.ClaimData memory data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: onchainidSetup.signatureValidator.getMetadataHash(1, ""),
            payload: ""
        });

        vm.prank(carol);
        bytes32 claimId = claims.addClaim(TOPIC, 1, address(issuer), "", data, "");

        vm.prank(alice);
        claims.removeClaim(claimId);

        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(TOPIC).length, 0, "the claim must be gone");
    }

}
