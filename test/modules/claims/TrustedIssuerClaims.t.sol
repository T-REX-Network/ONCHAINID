// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @title Trusted-issuer claim tests
/// @dev Exercises the trusted-issuer path of `addClaim` / `removeClaim`. A claim issuer
///      identity that holds no key on the target can write (and remove) its own claims when
///      it is the caller, its factory type record is CLAIM_ISSUER and its reputation meets
///      the global claim-add threshold.
contract TrustedIssuerClaimsTest is OnchainIDSetup {

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

    function test_trustedIssuerIdentity_canAddClaimWithoutKeyGrant() public {
        // claimIssuer is factory-deployed CLAIM_ISSUER and holds no key on aliceIdentity.
        // The identity itself is the caller, as when it executes a batched user operation.
        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerBefore,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerBefore, address(0));

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        vm.expectEmit(address(onchainidSetup.signatureValidator));
        emit IERC735.ClaimAdded(
            address(aliceIdentity), claimId, FRESH_TOPIC, scheme, issuer, signature, data, "", address(claimIssuer)
        );
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");

        (uint256 topic,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertEq(issuerAfter, address(claimIssuer));
    }

    /// @notice The issue-90 flow end to end: a MANAGEMENT key drives the Claim Issuer
    ///         Identity's own execution path, so the investor identity sees the issuer
    ///         identity as the caller and the trusted-issuer gate passes without any
    ///         key grant on the target.
    function test_trustedIssuerIdentity_canAddClaimThroughItsExecutionFlow() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        bytes memory call = abi.encodeCall(IERC735.addClaim, (FRESH_TOPIC, scheme, issuer, signature, data, ""));
        vm.prank(claimIssuerOwner);
        IKeyExecutor(address(claimIssuer)).execute(address(aliceIdentity), 0, call);

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (uint256 topic,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertEq(issuerAfter, address(claimIssuer));
    }

    function test_trustedIssuerIdentity_canRemoveItsOwnClaim() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).removeClaim(claimId);

        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    // ============ Negative paths ============

    function test_untrustedIssuer_revertsWithReputationBelowThreshold() public {
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_strangerCaller_revertsWithClaimSignerKey() public {
        // A keyless caller that is not the declared issuer never reaches the trusted gate.
        address stranger = makeAddr("stranger");
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(stranger);
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");
    }

    function test_trustedIssuer_cannotShipClaimDeclaringAnotherIssuer() public {
        // claimIssuer calls but declares bobIdentity as the issuer: caller != issuer, so
        // the keyless path is refused before any trust check.
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(bobIdentity), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");
    }

    function test_highScoreNonClaimIssuer_cannotAddClaim() public {
        // aliceIdentity is factory-deployed INDIVIDUAL. Even with a high score it must be
        // rejected: the gate is reserved for the CLAIM_ISSUER type record.
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(aliceIdentity), ISSUER_DEFAULT_SCORE);

        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, metadataHash: 0, payload: hex"01" });
        bytes memory signature = ClaimSignerHelper.signClaim(
            carolPk, carol, address(aliceIdentity), address(bobIdentity), FRESH_TOPIC, data
        );

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.IdentityNotClaimIssuerType.selector, address(aliceIdentity)));
        ERC734Validator(address(bobIdentity))
            .addClaim(FRESH_TOPIC, uint256(1), address(aliceIdentity), signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(aliceIdentity), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(bobIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_trustedIssuer_cannotRemoveAnotherIssuersClaim() public {
        // carol (CLAIM_SIGNER on aliceIdentity) stores a self-issued claim; claimIssuer
        // must not be able to remove it even though it is trusted.
        Structs.ClaimData memory data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: ClaimSignerHelper.metadataHash(1, ""),
            payload: hex"01"
        });
        bytes memory signature = ClaimSignerHelper.signClaim(
            carolPk, carol, address(aliceIdentity), address(aliceIdentity), FRESH_TOPIC, data
        );
        vm.prank(carol);
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, 1, address(aliceIdentity), signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(aliceIdentity), FRESH_TOPIC);
        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        ERC734Validator(address(aliceIdentity)).removeClaim(claimId);
    }

    function test_loseTrustAfterReputationLowered() public {
        (uint256 firstScheme, address firstIssuer, bytes memory firstSig, Structs.ClaimData memory firstData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, firstScheme, firstIssuer, firstSig, firstData, "");

        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        uint256 anotherTopic = 7777;
        (uint256 secondScheme, address secondIssuer, bytes memory secondSig, Structs.ClaimData memory secondData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), anotherTopic);

        vm.prank(address(claimIssuer));
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        ERC734Validator(address(aliceIdentity))
            .addClaim(anotherTopic, secondScheme, secondIssuer, secondSig, secondData, "");

        bytes32 secondClaimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), anotherTopic);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(secondClaimId);
        assertEq(issuerAfter, address(0));
    }

    // ============ Threshold boundary ============

    /// @dev Reputation exactly at the threshold passes; pins the `>=` semantic.
    function test_reputationExactlyAtThreshold_passes() public {
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), THRESHOLD);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(claimIssuer));
    }

    /// @dev Reputation one below the threshold fails; pins the other side of the boundary.
    function test_reputationOneBelowThreshold_reverts() public {
        uint128 belowThreshold = THRESHOLD - 1;
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), belowThreshold);

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), belowThreshold, THRESHOLD
            )
        );
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    /// @notice A claim on topic 0 is rejected: topic 0 is the "no claim" sentinel removeClaim
    ///         reads, so a stored topic-0 claim could never be removed.
    function test_addClaim_topicZero_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), 0);

        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.InvalidClaimTopic.selector);
        ERC734Validator(address(aliceIdentity)).addClaim(0, scheme, issuer, signature, data, "");
    }

    // ============ scheme and uri are bound through metadataHash ============

    /// @notice Re-presenting the issuer's unchanged signature with a different uri is refused:
    ///         the signed commitment no longer matches.
    function test_reAddClaim_sameSignature_differentUri_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://issuer-doc");

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://issuer-doc");

        vm.prank(address(claimIssuer));
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme, "ipfs://attacker-doc"));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://attacker-doc");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,,,,, string memory storedUri) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedUri, "ipfs://issuer-doc");
    }

    /// @notice scheme is inside the commitment on the same terms as the uri.
    function test_reAddClaim_sameSignature_differentScheme_reverts() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://issuer-doc");

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://issuer-doc");

        vm.prank(address(claimIssuer));
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme + 1, "ipfs://issuer-doc"));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme + 1, issuer, signature, data, "ipfs://issuer-doc");
    }

    /// @notice Replaying an older still-valid attestation with an arbitrary uri fails too:
    ///         the binding is per-attestation.
    function test_reAddClaim_olderAttestation_differentUri_reverts() public {
        (uint256 scheme, address issuer, bytes memory firstSig, Structs.ClaimData memory firstData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://v1");

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, firstSig, firstData, "ipfs://v1");

        (,, bytes memory secondSig, Structs.ClaimData memory secondData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://v2");
        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, secondSig, secondData, "ipfs://v2");

        vm.prank(address(claimIssuer));
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme, "ipfs://attacker"));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, firstSig, firstData, "ipfs://attacker");
    }

    /// @notice A fresh attestation committing to a new uri repoints the record in one call.
    function test_reAddClaim_freshCommitment_newUri_succeeds() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://typo");

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "ipfs://typo");

        (,, bytes memory newSig, Structs.ClaimData memory newData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://corrected");

        vm.prank(address(claimIssuer));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, scheme, issuer, newSig, newData, "ipfs://corrected");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,,,,, string memory storedUri) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedUri, "ipfs://corrected");
    }

    /// @notice The commitment is mandatory: a claim signed with metadataHash = 0 is rejected.
    function test_addClaim_zeroMetadataHash_reverts() public {
        Structs.ClaimData memory data =
            Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, metadataHash: 0, payload: hex"01" });
        bytes memory signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(claimIssuer), address(aliceIdentity), FRESH_TOPIC, data
        );

        vm.prank(address(claimIssuer));
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, uint256(1), "ipfs://any"));
        ERC734Validator(address(aliceIdentity))
            .addClaim(FRESH_TOPIC, 1, address(claimIssuer), signature, data, "ipfs://any");
    }

    /// @notice The published helper produces the hash the add path checks against.
    function test_getMetadataHash_matchesTheCheckedCommitment() public view {
        assertEq(
            onchainidSetup.signatureValidator.getMetadataHash(7, "ipfs://doc"),
            keccak256(
                abi.encode(keccak256("Metadata(uint256 scheme,string uri)"), uint256(7), keccak256(bytes("ipfs://doc")))
            )
        );
    }

    // ============ Helper ============

    /// @dev Build the four signed-claim components for the trusted-issuer path. Signed by
    ///      `claimIssuerOwner`, a CLAIM_SIGNER on the issuer identity, committed to scheme 1
    ///      and an empty uri.
    function _buildSignedClaim(address targetIdentity, address declaredIssuer, uint256 topic)
        internal
        view
        returns (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data)
    {
        data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: ClaimSignerHelper.metadataHash(1, ""),
            payload: hex"01"
        });
        signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, declaredIssuer, targetIdentity, topic, data
        );
        scheme = 1;
        issuer = declaredIssuer;
    }

    /// @dev Like {_buildSignedClaim} but targeting aliceIdentity with claimIssuer as the
    ///      declared issuer, committed to the given scheme and uri.
    function _buildCommittedClaim(uint256 topic, uint256 scheme_, string memory uri)
        internal
        view
        returns (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data)
    {
        data = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: ClaimSignerHelper.metadataHash(scheme_, uri),
            payload: hex"01"
        });
        signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(claimIssuer), address(aliceIdentity), topic, data
        );
        scheme = scheme_;
        issuer = address(claimIssuer);
    }

}
