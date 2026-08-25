// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
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
        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerBefore,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerBefore, address(0));

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");

        (uint256 topic,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertEq(issuerAfter, address(claimIssuer));
    }

    // ============ Negative paths ============

    function test_untrustedIssuer_revertsWithReputationBelowThreshold() public {
        // Drop claimIssuer's reputation below threshold.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_callerNotLinkedToAnyIdentity_revertsWithCallerNotLinked() public {
        // A wallet the factory does not know cannot use this path.
        address stranger = makeAddr("stranger");
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Errors.CallerNotLinkedToFactoryIdentity.selector, stranger));
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");
    }

    function test_declaredIssuerMismatch_revertsWithMismatchError() public {
        // claimIssuerOwner resolves to claimIssuer, but the call declares bobIdentity
        // as the issuer. Reject so a trusted issuer cannot ship a claim attributed to
        // someone else.
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(bobIdentity), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.DeclaredIssuerMismatch.selector, address(bobIdentity), address(claimIssuer))
        );
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");
    }

    function test_highScoreNonClaimIssuer_cannotAddClaim() public {
        // The trusted-issuer path must reject any identity that is not type
        // CLAIM_ISSUER, even when its reputation is at or above the threshold.
        // Without the explicit type check, a REPUTATION_MANAGER giving a non-issuer
        // a high score for any reason would silently grant it claim-add capability.
        //
        // Setup: aliceIdentity is factory-deployed INDIVIDUAL. Give it a high score
        // and try to attest to bobIdentity. Carol is alice's CLAIM_SIGNER, so the
        // claim signature itself is valid; the new gate is what rejects.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(aliceIdentity), ISSUER_DEFAULT_SCORE);

        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: hex"01" });
        bytes memory signature = ClaimSignerHelper.signClaim(
            carolPk, carol, address(aliceIdentity), address(bobIdentity), FRESH_TOPIC, data
        );

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.IdentityNotClaimIssuerType.selector, address(aliceIdentity)));
        ERC734Validator(address(bobIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, uint256(1), address(aliceIdentity), signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(aliceIdentity), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(bobIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_loseTrustAfterReputationLowered() public {
        // First write succeeds (score 50, threshold 50).
        (uint256 firstScheme, address firstIssuer, bytes memory firstSig, Structs.ClaimData memory firstData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, firstScheme, firstIssuer, firstSig, firstData, "");

        // Manager lowers the score. A subsequent attempt for a different topic must
        // revert with the threshold error.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        uint256 anotherTopic = 7777;
        (uint256 secondScheme, address secondIssuer, bytes memory secondSig, Structs.ClaimData memory secondData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), anotherTopic);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(anotherTopic, secondScheme, secondIssuer, secondSig, secondData, "");

        bytes32 secondClaimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), anotherTopic);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(secondClaimId);
        assertEq(issuerAfter, address(0));
    }

    // ============ Threshold boundary ============

    /// @dev Issuer with reputation exactly equal to the threshold passes the gate. Pins
    ///      the `>=` semantic; a future change to `>` would break this test.
    function test_reputationExactlyAtThreshold_passes() public {
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), THRESHOLD);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(claimIssuer));
    }

    /// @dev Issuer with reputation one below the threshold fails. Pins the other side of
    ///      the boundary so an off-by-one in the comparison gets caught by tests.
    function test_reputationOneBelowThreshold_reverts() public {
        uint128 belowThreshold = THRESHOLD - 1;
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), belowThreshold);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), belowThreshold, THRESHOLD
            )
        );
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    /// @notice A claim on topic 0 is rejected. Topic 0 is the "no claim" sentinel removeClaim
    ///         reads, so a stored topic-0 claim could never be removed.
    function test_addClaim_topicZero_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), 0);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.InvalidClaimTopic.selector);
        ERC734Validator(address(aliceIdentity)).addClaimByTrustedIssuer(0, scheme, issuer, signature, data, "");
    }

    // ============ scheme / uri are pinned on re-add ============

    /// @notice Neither scheme nor uri is covered by the claim signature, so re-presenting the
    ///         issuer's own unchanged signature with a different uri would repoint the stored
    ///         record while it still reads as issuer-attested. The overwrite is rejected.
    function test_reAddClaim_withDifferentUri_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://issuer-doc");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);

        // Same issuer, same signature, same data — only the uri changes.
        vm.prank(claimIssuerOwner);
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataImmutable.selector, claimId));
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://attacker-doc");

        (,,,,, string memory storedUri) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedUri, "ipfs://issuer-doc");
    }

    /// @notice scheme is pinned on the same terms as uri.
    function test_reAddClaim_withDifferentScheme_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataImmutable.selector, claimId));
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme + 1, issuer, signature, data, "");
    }

    /// @notice Re-adding with both fields unchanged still refreshes the claim, so an issuer can
    ///         re-attest with new data without first removing the record.
    function test_reAddClaim_withSameMetadata_succeeds() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://issuer-doc");

        // A fresh signature over new data, same scheme and uri.
        Structs.ClaimData memory newData =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: hex"02" });
        bytes memory newSignature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(claimIssuer), address(aliceIdentity), FRESH_TOPIC, newData
        );

        vm.prank(claimIssuerOwner);
        ERC734Validator(address(aliceIdentity))
            .addClaimByTrustedIssuer(FRESH_TOPIC, scheme, issuer, newSignature, newData, "ipfs://issuer-doc");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,,,, Structs.ClaimData memory storedData,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedData.payload, hex"02");
    }

    // ============ Helper ============

    /// @dev Build the four signed-claim components used by addClaimByTrustedIssuer.
    ///      Signed by `claimIssuerOwner`, who is a CLAIM_SIGNER on `claimIssuer`'s
    ///      identity. Carol-signed claims are built inline in the tests that need them.
    function _buildSignedClaim(address targetIdentity, address declaredIssuer, uint256 topic)
        internal
        view
        returns (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data)
    {
        data = Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: hex"01" });
        signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, declaredIssuer, targetIdentity, topic, data
        );
        scheme = 1;
        issuer = declaredIssuer;
    }

}
