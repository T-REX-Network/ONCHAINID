// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @title Trusted-issuer claim tests
/// @dev Exercises the trusted-issuer path of `addClaim` / `removeClaim`. A claim issuer
///      identity that holds no key on the target can write (and remove) its own claims through
///      its `addClaimTo` / `removeClaimFrom`, sent by one of its MANAGEMENT keys, when its
///      factory type record is CLAIM_ISSUER and its reputation meets the global claim-add
///      threshold.
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

    function test_trustedIssuer_canAddClaimWithoutKeyGrant() public {
        // claimIssuer is factory-deployed CLAIM_ISSUER and holds no key on aliceIdentity.
        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerBefore,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerBefore, address(0));

        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        // The target records the issuer identity as the caller, whichever issuer key sent it.
        vm.expectEmit(address(onchainidSetup.signatureValidator));
        emit IERC735.ClaimAdded(
            address(aliceIdentity), claimId, FRESH_TOPIC, scheme, issuer, signature, data, "", address(claimIssuer)
        );
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        (uint256 topic,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertEq(issuerAfter, address(claimIssuer));
    }

    function test_trustedIssuer_canRemoveItsOwnClaimWithoutKeyGrant() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        vm.expectEmit(address(onchainidSetup.signatureValidator));
        emit ERC734Validator.ClaimRemovedFrom(address(aliceIdentity), FRESH_TOPIC, claimIssuerOwner);
        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).removeClaimFrom(FRESH_TOPIC, IIdentity(address(aliceIdentity)));

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
        assertFalse(
            IClaimIssuer(address(claimIssuer))
                .isClaimValid(IIdentity(address(aliceIdentity)), FRESH_TOPIC, signature, data)
        );
    }

    /// @notice A target that granted the issuer identity CLAIM_SIGNER authorized it itself, so a
    ///         direct call from the issuer identity still works.
    function test_issuerWithKeyGrant_canAddAndRemoveDirectly() public {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(address(claimIssuer)),
            KeyPurposes.CLAIM_SIGNER,
            KeyTypes.ECDSA,
            abi.encodePacked(address(claimIssuer)),
            ""
        );
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

    // ============ Only a MANAGEMENT key of the issuer opens the keyless path ============

    function test_addClaim_RevertWhen_TheIssuerIdentityCallsTheTargetDirectlyWithoutAGrant() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        ERC734Validator(address(aliceIdentity)).addClaim(FRESH_TOPIC, scheme, issuer, signature, data, "");
    }

    function test_removeClaim_RevertWhen_TheIssuerIdentityCallsTheTargetDirectlyWithoutAGrant() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        vm.prank(address(claimIssuer));
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        ERC734Validator(address(aliceIdentity)).removeClaim(claimId);
    }

    /// @notice An ACTION key of the issuer can make the issuer identity call any external
    ///         target. That call must not remove the issuer's claims from holders.
    function test_anIssuerActionKey_cannotRemoveTheIssuersClaimThroughExecute() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        address actionKey = _addActionKeyOnIssuer();
        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        vm.prank(actionKey);
        IKeyExecutor(address(claimIssuer))
            .execute(address(aliceIdentity), 0, abi.encodeCall(IERC735.removeClaim, (claimId)));

        (uint256 topic,,,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, FRESH_TOPIC);
        assertTrue(
            IClaimIssuer(address(claimIssuer))
                .isClaimValid(IIdentity(address(aliceIdentity)), FRESH_TOPIC, signature, data)
        );
    }

    /// @notice The same ACTION key cannot push a claim through execute either.
    function test_anIssuerActionKey_cannotAddAClaimThroughExecute() public {
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        address actionKey = _addActionKeyOnIssuer();
        bytes memory call = abi.encodeCall(IERC735.addClaim, (FRESH_TOPIC, scheme, issuer, signature, data, ""));
        vm.prank(actionKey);
        IKeyExecutor(address(claimIssuer)).execute(address(aliceIdentity), 0, call);

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_removeClaimFrom_RevertWhen_TheCallerIsAnIssuerActionKey() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        address actionKey = _addActionKeyOnIssuer();
        vm.prank(actionKey);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IClaimIssuer(address(claimIssuer)).removeClaimFrom(FRESH_TOPIC, IIdentity(address(aliceIdentity)));
    }

    // ============ Negative paths ============

    function test_untrustedIssuer_revertsWithReputationBelowThreshold() public {
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_removeClaimFrom_RevertWhen_TheIssuerLostTrust() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        vm.prank(claimIssuerOwner);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        IClaimIssuer(address(claimIssuer)).removeClaimFrom(FRESH_TOPIC, IIdentity(address(aliceIdentity)));
    }

    function test_strangerCaller_revertsWithClaimSignerKey() public {
        // A keyless caller that is not the issuer's addClaimTo never reaches the trusted gate.
        address stranger = makeAddr("stranger");
        (uint256 scheme, address issuer, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.prank(stranger);
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

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.IdentityNotClaimIssuerType.selector, address(aliceIdentity)));
        IClaimIssuer(address(aliceIdentity))
            .addClaimTo(FRESH_TOPIC, uint256(1), signature, data, "", IIdentity(address(bobIdentity)));

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(aliceIdentity), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(bobIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    function test_removeClaimFrom_cannotReachAnotherIssuersClaim() public {
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

        // removeClaimFrom builds the id from the issuer's own address, so it names a claim
        // that does not exist rather than carol's.
        bytes32 issuerClaimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        vm.prank(claimIssuerOwner);
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimNotRegistered.selector, issuerClaimId));
        IClaimIssuer(address(claimIssuer)).removeClaimFrom(FRESH_TOPIC, IIdentity(address(aliceIdentity)));

        bytes32 carolClaimId = ClaimSignerHelper.computeClaimId(address(aliceIdentity), FRESH_TOPIC);
        (uint256 topic,,,,,) = IIdentity(address(aliceIdentity)).getClaim(carolClaimId);
        assertEq(topic, FRESH_TOPIC);
    }

    function test_loseTrustAfterReputationLowered() public {
        (uint256 firstScheme,, bytes memory firstSig, Structs.ClaimData memory firstData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, firstScheme, firstSig, firstData, "");

        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), 0);

        uint256 anotherTopic = 7777;
        (uint256 secondScheme,, bytes memory secondSig, Structs.ClaimData memory secondData) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), anotherTopic);

        vm.expectRevert(
            abi.encodeWithSelector(Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), 0, THRESHOLD)
        );
        _addClaimToAlice(anotherTopic, secondScheme, secondSig, secondData, "");

        bytes32 secondClaimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), anotherTopic);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(secondClaimId);
        assertEq(issuerAfter, address(0));
    }

    // ============ Threshold boundary ============

    /// @dev Reputation exactly at the threshold passes; pins the `>=` semantic.
    function test_reputationExactlyAtThreshold_passes() public {
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), THRESHOLD);

        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(claimIssuer));
    }

    /// @dev Reputation one below the threshold fails; pins the other side of the boundary.
    function test_reputationOneBelowThreshold_reverts() public {
        uint128 belowThreshold = THRESHOLD - 1;
        vm.prank(reputationManager);
        onchainidSetup.reputationRegistry.setReputation(address(claimIssuer), belowThreshold);

        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), FRESH_TOPIC);

        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.ReputationBelowClaimAddThreshold.selector, address(claimIssuer), belowThreshold, THRESHOLD
            )
        );
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,, address issuerAfter,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(issuerAfter, address(0));
    }

    /// @notice A claim on topic 0 is rejected: topic 0 is the "no claim" sentinel removeClaim
    ///         reads, so a stored topic-0 claim could never be removed.
    function test_addClaim_topicZero_reverts() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildSignedClaim(address(aliceIdentity), address(claimIssuer), 0);

        vm.expectRevert(Errors.InvalidClaimTopic.selector);
        _addClaimToAlice(0, scheme, signature, data, "");
    }

    // ============ scheme and uri are bound through metadataHash ============

    /// @notice Re-presenting the issuer's unchanged signature with a different uri is refused:
    ///         the signed commitment no longer matches.
    function test_reAddClaim_sameSignature_differentUri_reverts() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://issuer-doc");
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "ipfs://issuer-doc");

        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme, "ipfs://attacker-doc"));
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "ipfs://attacker-doc");

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), FRESH_TOPIC);
        (,,,,, string memory storedUri) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedUri, "ipfs://issuer-doc");
    }

    /// @notice scheme is inside the commitment on the same terms as the uri.
    function test_reAddClaim_sameSignature_differentScheme_reverts() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://issuer-doc");
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "ipfs://issuer-doc");

        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme + 1, "ipfs://issuer-doc"));
        _addClaimToAlice(FRESH_TOPIC, scheme + 1, signature, data, "ipfs://issuer-doc");
    }

    /// @notice Replaying an older still-valid attestation with an arbitrary uri fails too:
    ///         the binding is per-attestation.
    function test_reAddClaim_olderAttestation_differentUri_reverts() public {
        (uint256 scheme,, bytes memory firstSig, Structs.ClaimData memory firstData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://v1");
        _addClaimToAlice(FRESH_TOPIC, scheme, firstSig, firstData, "ipfs://v1");

        (,, bytes memory secondSig, Structs.ClaimData memory secondData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://v2");
        _addClaimToAlice(FRESH_TOPIC, scheme, secondSig, secondData, "ipfs://v2");

        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, scheme, "ipfs://attacker"));
        _addClaimToAlice(FRESH_TOPIC, scheme, firstSig, firstData, "ipfs://attacker");
    }

    /// @notice A fresh attestation committing to a new uri repoints the record in one call.
    function test_reAddClaim_freshCommitment_newUri_succeeds() public {
        (uint256 scheme,, bytes memory signature, Structs.ClaimData memory data) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://typo");
        _addClaimToAlice(FRESH_TOPIC, scheme, signature, data, "ipfs://typo");

        (,, bytes memory newSig, Structs.ClaimData memory newData) =
            _buildCommittedClaim(FRESH_TOPIC, 1, "ipfs://corrected");
        _addClaimToAlice(FRESH_TOPIC, scheme, newSig, newData, "ipfs://corrected");

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

        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimMetadataMismatch.selector, uint256(1), "ipfs://any"));
        _addClaimToAlice(FRESH_TOPIC, 1, signature, data, "ipfs://any");
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

    /// @dev The issuer's MANAGEMENT key pushes a claim to aliceIdentity through `addClaimTo`.
    function _addClaimToAlice(
        uint256 topic,
        uint256 scheme,
        bytes memory signature,
        Structs.ClaimData memory data,
        string memory uri
    ) internal {
        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(topic, scheme, signature, data, uri, IIdentity(address(aliceIdentity)));
    }

    /// @dev Grants a fresh key ACTION, and nothing else, on the issuer identity.
    function _addActionKeyOnIssuer() internal returns (address actionKey) {
        actionKey = makeAddr("issuerActionKey");
        vm.prank(claimIssuerOwner);
        claimIssuer.addKeyWithData(
            ClaimSignerHelper.addressToKey(actionKey),
            KeyPurposes.ACTION,
            KeyTypes.ECDSA,
            abi.encodePacked(actionKey),
            ""
        );
    }

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
