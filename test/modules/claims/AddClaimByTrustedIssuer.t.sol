// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @title ClaimsModule.addClaimByTrustedIssuer tests
/// @dev Exercises the trusted-issuer path. A wallet that holds no key on the target
///      identity can still write a claim if it resolves through the factory to an
///      issuer identity whose reputation meets the global claim-add threshold.
contract AddClaimAsTrustedIssuerTest is OnchainIDSetup {

    uint64 internal constant REPUTATION_MANAGER_ROLE = 1001;

    uint128 internal constant ISSUER_DEFAULT_SCORE = 50;
    uint128 internal constant THRESHOLD = 50;

    /// @dev Topic distinct from the one OnchainIDSetup pre-populates, so assertions
    ///      start from a clean slate.
    uint256 internal constant FRESH_TOPIC = 4242;

    address internal reputationManager;

    function setUp() public override {
        super.setUp();
        reputationManager = makeAddr("reputationManager");

        ReputationRegistry registry = onchainidSetup.reputationRegistry;

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = ReputationRegistry.setReputation.selector;
        selectors[1] = ReputationRegistry.setDefault.selector;
        selectors[2] = ReputationRegistry.setClaimAddThreshold.selector;

        vm.startPrank(deployer);
        onchainidSetup.accessManager.setTargetFunctionRole(address(registry), selectors, REPUTATION_MANAGER_ROLE);
        onchainidSetup.accessManager.grantRole(REPUTATION_MANAGER_ROLE, reputationManager, 0);
        vm.stopPrank();

        vm.startPrank(reputationManager);
        registry.setDefault(IdentityTypes.CLAIM_ISSUER, ISSUER_DEFAULT_SCORE);
        registry.setClaimAddThreshold(THRESHOLD);
        vm.stopPrank();
    }

    // ============ Positive path ============

    function test_trustedIssuer_canAddClaimWithoutKeyGrant() public {
        // claimIssuer is factory-deployed CLAIM_ISSUER; claimIssuerOwner is its auto-linked
        // wallet. No key has been granted on aliceIdentity for claimIssuerOwner.
        bytes memory addClaimData = _buildAddClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);

        (,, address issuerBefore,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerBefore, address(0));

        vm.prank(claimIssuerOwner);
        (bool ok,) = address(aliceIdentity).call(addClaimData);
        assertTrue(ok);

        (uint256 topic,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertEq(issuerAfter, address(claimIssuer));
    }

    // ============ Negative paths ============

    function test_untrustedIssuer_reverts() public {
        // Drop claimIssuer's reputation below threshold.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        bytes memory addClaimData = _buildAddClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        (bool ok,) = address(aliceIdentity).call(addClaimData);
        assertFalse(ok);

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_callerNotLinkedToAnyIdentity_reverts() public {
        // A wallet the factory does not know cannot use this path even with a valid
        // signature.
        address stranger = makeAddr("stranger");
        bytes memory addClaimData = _buildAddClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(stranger);
        (bool ok,) = address(aliceIdentity).call(addClaimData);
        assertFalse(ok);
    }

    function test_declaredIssuerMismatch_reverts() public {
        // claimIssuerOwner resolves to claimIssuer, but the call declares bobIdentity
        // as the issuer. Reject so a trusted issuer cannot ship a claim attributed to
        // someone else.
        bytes memory addClaimData = _buildAddClaim(address(aliceIdentity), address(bobIdentity), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        (bool ok,) = address(aliceIdentity).call(addClaimData);
        assertFalse(ok);
    }

    function test_loseTrustAfterReputationLowered() public {
        // First write succeeds (score 50, threshold 50).
        bytes memory firstAdd = _buildAddClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        vm.prank(claimIssuerOwner);
        (bool okFirst,) = address(aliceIdentity).call(firstAdd);
        assertTrue(okFirst);

        // Manager lowers the score. A subsequent attempt for a different topic must fail.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        uint256 anotherTopic = 7777;
        bytes memory secondAdd = _buildAddClaim(address(aliceIdentity), address(claimIssuer), anotherTopic);
        vm.prank(claimIssuerOwner);
        (bool okSecond,) = address(aliceIdentity).call(secondAdd);
        assertFalse(okSecond);

        bytes32 secondClaimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), anotherTopic);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(secondClaimId);
        assertEq(issuerAfter, address(0));
    }

    // ============ Helper ============

    function _buildAddClaim(address targetIdentity, address declaredIssuer, uint256 topic)
        internal
        view
        returns (bytes memory)
    {
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: hex"01" });
        bytes memory signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, declaredIssuer, targetIdentity, topic, data
        );
        return abi.encodeCall(
            ClaimsModule.addClaimByTrustedIssuer, (topic, uint256(1), declaredIssuer, signature, data, "")
        );
    }

}
