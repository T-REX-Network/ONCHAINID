// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC735 } from "contracts/interface/IERC735.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { MockMalformedDomainIssuer } from "../../mocks/MockMalformedDomainIssuer.sol";

/// @notice Removing a claim must not depend on the issuer: one whose `eip712Domain` answers
///         with data that does not decode as a domain, or burns all its gas, must not make its
///         claim unremovable or expensive to remove.
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

    /// @notice An issuer that burns all the gas it gets cannot make removal expensive: removal
    ///         never calls the issuer, so an ordinary gas limit is enough.
    function test_claimFromIssuerThatBurnsAllGas_canBeRemovedWithNormalGas() public {
        issuer.setMode(MockMalformedDomainIssuer.Mode.BurnsAllGas);
        ERC734Validator claims = ERC734Validator(address(aliceIdentity));
        bytes32 claimId = _addClaimAsCarol();

        vm.prank(alice);
        claims.removeClaim{ gas: 300_000 }(claimId);

        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(TOPIC).length, 0, "the claim must be gone");
    }

    /// @dev carol adds a claim from `issuer`, then alice (MANAGEMENT) removes it.
    function _addAndRemoveAsManagement() internal {
        ERC734Validator claims = ERC734Validator(address(aliceIdentity));
        bytes32 claimId = _addClaimAsCarol();

        vm.prank(alice);
        claims.removeClaim(claimId);

        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(TOPIC).length, 0, "the claim must be gone");
    }

    /// @dev carol (CLAIM_SIGNER) adds a claim from `issuer` and returns its id.
    function _addClaimAsCarol() internal returns (bytes32 claimId) {
        ERC734Validator claims = ERC734Validator(address(aliceIdentity));
        Structs.ClaimData memory data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: onchainidSetup.signatureValidator.getMetadataHash(1, ""),
            payload: ""
        });

        vm.prank(carol);
        claimId = claims.addClaim(TOPIC, 1, address(issuer), "", data, "");
    }

}
