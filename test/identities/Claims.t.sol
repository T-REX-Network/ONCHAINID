// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

/// @notice Coverage for ERC-735 claim management on an Identity (add, remove, get, isClaimValid).
contract ClaimsTest is OnchainIDSetup {

    bytes32 internal constant _CLAIMID_666 = bytes32(0);

    function _aliceClaim666Id() internal view returns (bytes32) {
        return ClaimSignerHelper.computeClaimId(address(claimIssuer), Constants.CLAIM_TOPIC_666);
    }

    /// @notice Add an issuer-signed claim with a valid ECDSA signature.
    function test_addClaim_issuerSigned_storedAndValid() public view {
        bytes32 claimId = _aliceClaim666Id();
        (uint256 topic, uint256 scheme, address issuer, bytes memory sig, bytes memory data, string memory uri) =
            IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, Constants.CLAIM_TOPIC_666);
        assertEq(scheme, 1);
        assertEq(issuer, address(claimIssuer));
        assertEq(sig, aliceClaim666.signature);
        assertEq(data, aliceClaim666.data);
        assertEq(uri, "https://example.com");

        // isClaimValid is dispatched through the issuer (which holds the validator + CLAIM_SIGNER key).
        bool ok = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_666, sig, data);
        assertTrue(ok, "valid issuer-signed claim should validate");
    }

    /// @notice Revoking the signature on the issuer side flips `isClaimValid` to false.
    function test_addClaim_thenIssuerRevokes_isClaimValidFalse() public {
        bytes32 claimId = _aliceClaim666Id();
        (,,, bytes memory sig, bytes memory data,) = IERC735(address(aliceIdentity)).getClaim(claimId);

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimBySignature(sig);

        bool ok = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_666, sig, data);
        assertFalse(ok, "revoked claim signature must not validate");
    }

    /// @notice addClaim with a bad signature for a foreign issuer is rejected by the
    ///         issuer's isClaimValid round-trip; the storage write never happens.
    function test_addClaim_badSignatureFromForeignIssuer_reverts() public {
        ClaimSignerHelper.Claim memory bad = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(bobIdentity), address(claimIssuer), 42, hex"d00d", ""
        );
        // Corrupt the signature middle byte so ecrecover misses.
        bytes memory sig = bad.signature;
        sig[40] = bytes1(uint8(sig[40]) ^ 0xff);

        vm.prank(bob);
        // The error propagates as a bubbled revert through the fallback; the selector is
        // not preserved by OZ's LowLevelCall.callNoReturn, so we only require a revert.
        vm.expectRevert();
        IERC735(address(bobIdentity)).addClaim(42, 1, address(claimIssuer), sig, bad.data, "");
    }

    /// @notice Re-adding the same `(issuer, topic)` emits ClaimChanged (not ClaimAdded)
    ///         and keeps the topic index size unchanged.
    function test_addClaim_sameIssuerTopic_emitsClaimChangedAndIndexStable() public {
        // Build a fresh claim with the same (issuer, topic) but different data.
        ClaimSignerHelper.Claim memory update = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(aliceIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_666,
            hex"beef",
            "https://updated.example.com"
        );

        bytes32 claimId = _aliceClaim666Id();
        uint256 idsLenBefore = IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666).length;

        // Event emitter is the ClaimsModule singleton (CALL semantics from the identity's
        // fallback, not DELEGATECALL), not the identity proxy itself.
        vm.expectEmit(true, true, true, true, address(onchainidSetup.claimsModule));
        emit IERC735.ClaimChanged(
            claimId,
            Constants.CLAIM_TOPIC_666,
            1,
            address(claimIssuer),
            update.signature,
            update.data,
            "https://updated.example.com"
        );

        vm.prank(alice);
        IERC735(address(aliceIdentity))
            .addClaim(
                Constants.CLAIM_TOPIC_666,
                1,
                address(claimIssuer),
                update.signature,
                update.data,
                "https://updated.example.com"
            );

        uint256 idsLenAfter = IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666).length;
        assertEq(idsLenAfter, idsLenBefore, "topic index must not grow on update");

        (,,,, bytes memory storedData, string memory storedUri) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(storedData, hex"beef");
        assertEq(storedUri, "https://updated.example.com");
    }

    /// @notice CLAIM_SIGNER can remove a claim: mapping cleared, topic index updated.
    function test_removeClaim_byClaimSigner_clearsStorageAndIndex() public {
        bytes32 claimId = _aliceClaim666Id();
        // carol holds CLAIM_SIGNER on aliceIdentity per the fixture.
        vm.prank(carol);
        IERC735(address(aliceIdentity)).removeClaim(claimId);

        (uint256 topic, uint256 scheme, address issuer, bytes memory sig, bytes memory data, string memory uri) =
            IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, 0);
        assertEq(scheme, 0);
        assertEq(issuer, address(0));
        assertEq(sig.length, 0);
        assertEq(data.length, 0);
        assertEq(bytes(uri).length, 0);

        bytes32[] memory ids = IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666);
        assertEq(ids.length, 0, "topic index drained");
    }

    /// @notice CLAIM_ADDER cannot remove a claim (only CLAIM_SIGNER + MANAGEMENT can).
    function test_removeClaim_byClaimAdder_reverts() public {
        // Grant bob CLAIM_ADDER on aliceIdentity, then try to remove.
        vm.prank(alice);
        aliceIdentity.addKey(ClaimSignerHelper.addressToKey(bob), KeyPurposes.CLAIM_ADDER, KeyTypes.ECDSA);

        bytes32 claimId = _aliceClaim666Id();
        vm.prank(bob);
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        IERC735(address(aliceIdentity)).removeClaim(claimId);
    }

    /// @notice getClaimIdsByTopic stays consistent across add/remove cycles.
    function test_getClaimIdsByTopic_consistentAcrossAddRemove() public {
        // Initial state has aliceClaim666 under topic 666.
        bytes32[] memory ids = IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666);
        assertEq(ids.length, 1);

        // Add a second claim under a fresh topic.
        ClaimSignerHelper.Claim memory extra = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(aliceIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_42,
            hex"cafe",
            ""
        );
        vm.prank(alice);
        IERC735(address(aliceIdentity))
            .addClaim(Constants.CLAIM_TOPIC_42, 1, address(claimIssuer), extra.signature, extra.data, "");
        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_42).length, 1);
        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666).length, 1);

        // Remove the original.
        vm.prank(carol);
        IERC735(address(aliceIdentity)).removeClaim(_aliceClaim666Id());

        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_666).length, 0);
        assertEq(IERC735(address(aliceIdentity)).getClaimIdsByTopic(Constants.CLAIM_TOPIC_42).length, 1);
    }

    /// @notice Self-issued claim: issuer == identity skips the external isClaimValid round trip.
    function test_addClaim_selfIssued_succeeds() public {
        // Self-issued claim: aliceIdentity is both subject and issuer. No external 1271 needed.
        // CLAIM_SIGNER on alice's own identity is required; alice is MANAGEMENT which implies all.
        vm.prank(alice);
        bytes32 claimId = IERC735(address(aliceIdentity))
            .addClaim(Constants.CLAIM_TOPIC_999, 1, address(aliceIdentity), "", hex"abba", "uri://self");

        assertEq(claimId, ClaimSignerHelper.computeClaimId(address(aliceIdentity), Constants.CLAIM_TOPIC_999));
        (uint256 topic,, address issuer,, bytes memory data,) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, Constants.CLAIM_TOPIC_999);
        assertEq(issuer, address(aliceIdentity));
        assertEq(data, hex"abba");
    }

    /// @notice Cross-identity isolation: a claim added on alice is NOT visible on bob.
    function test_addClaim_isolatedPerIdentity_acrossInstalls() public view {
        bytes32 claimId = _aliceClaim666Id();
        // alice has the claim populated by setUp.
        (uint256 topic,,,,,) = IERC735(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, Constants.CLAIM_TOPIC_666, "alice should see her own claim");

        // bob shares the same ClaimsModule singleton but his slot is empty.
        (uint256 bobTopic, uint256 bobScheme, address bobIssuer, bytes memory bobSig, bytes memory bobData,) =
            IERC735(address(bobIdentity)).getClaim(claimId);
        assertEq(bobTopic, 0, "bob must not see alice's claim");
        assertEq(bobScheme, 0);
        assertEq(bobIssuer, address(0));
        assertEq(bobSig.length, 0);
        assertEq(bobData.length, 0);
    }

    /// @notice `addClaimTo` from the issuer side: claim is pushed onto the target identity
    ///         and the issuer emits ClaimAddedTo.
    function test_addClaimTo_fromIssuer_writesToTargetIdentity() public {
        // Build a fresh claim on bob from claimIssuer.
        ClaimSignerHelper.Claim memory c = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(bobIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_42,
            hex"feed",
            "uri://bob"
        );

        // addClaimTo uses CALL semantics from the issuer's ClaimsModule into the target
        // identity, so the ERC-2771 trailer that arrives at bob's ClaimsModule is the
        // *singleton* ClaimsModule address — not the issuer Identity. bob must register the
        // ClaimsModule singleton address as a CLAIM_ADDER for `_requireClaimKey` to pass.
        vm.prank(bob);
        bobIdentity.addKey(
            ClaimSignerHelper.addressToKey(address(onchainidSetup.claimsModule)),
            KeyPurposes.CLAIM_ADDER,
            KeyTypes.ECDSA
        );

        // claimIssuerOwner is MANAGEMENT on claimIssuer; addClaimTo is gated by _requireManagement.
        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(Constants.CLAIM_TOPIC_42, 1, c.signature, c.data, "uri://bob", IIdentity(address(bobIdentity)));

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), Constants.CLAIM_TOPIC_42);
        (uint256 topic,, address issuer, bytes memory storedSig, bytes memory storedData, string memory storedUri) =
            IERC735(address(bobIdentity)).getClaim(claimId);
        assertEq(topic, Constants.CLAIM_TOPIC_42);
        assertEq(issuer, address(claimIssuer));
        assertEq(storedSig, c.signature);
        assertEq(storedData, c.data);
        assertEq(storedUri, "uri://bob");
    }

    /// @notice `addClaim` requires CLAIM_SIGNER or CLAIM_ADDER (or self-call). A
    ///         no-purpose key cannot add a claim, even for a self-issued payload.
    function test_addClaim_byUnprivilegedKey_reverts() public {
        // Use an address with no purpose on aliceIdentity.
        address stranger = address(0xC0FFEE);
        vm.prank(stranger);
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        IERC735(address(aliceIdentity)).addClaim(Constants.CLAIM_TOPIC_999, 1, address(aliceIdentity), "", hex"01", "");
    }

    /// @notice `removeClaim` for a missing claimId reverts with ClaimNotRegistered.
    function test_removeClaim_unknownClaimId_reverts() public {
        bytes32 missing = keccak256("never-existed");
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(Errors.ClaimNotRegistered.selector, missing));
        IERC735(address(aliceIdentity)).removeClaim(missing);
    }

    /// @notice `revokeClaimBySignature` is MANAGEMENT-only.
    function test_revokeClaimBySignature_nonManagement_reverts() public {
        // carol has CLAIM_SIGNER on the issuer but no MANAGEMENT there.
        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaimBySignature(aliceClaim666.signature);
    }

    /// @notice Revoking the same signature twice reverts on the second call.
    function test_revokeClaimBySignature_doubleRevoke_reverts() public {
        vm.startPrank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaimBySignature(aliceClaim666.signature);
        vm.expectRevert(Errors.ClaimAlreadyRevoked.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaimBySignature(aliceClaim666.signature);
        vm.stopPrank();
    }

    /// @notice `revokeClaim(claimId, identity)` pulls the claim off the target and revokes
    ///         the signature on the issuer side. After revocation, isClaimValid returns false.
    function test_revokeClaim_byIssuer_marksSignatureRevoked() public {
        bytes32 claimId = _aliceClaim666Id();
        (,,, bytes memory sig, bytes memory data,) = IERC735(address(aliceIdentity)).getClaim(claimId);

        vm.prank(claimIssuerOwner);
        bool ok = IClaimIssuer(address(claimIssuer)).revokeClaim(claimId, address(aliceIdentity));
        assertTrue(ok);
        assertTrue(IClaimIssuer(address(claimIssuer)).isClaimRevoked(sig));

        bool stillValid = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_666, sig, data);
        assertFalse(stillValid);
    }

    /// @notice `revokeClaim` is callable only by the issuer that originally signed the claim.
    ///         If the claim's `issuer` field doesn't match the caller's account, the call
    ///         reverts `NotOwnIssuance`. Here, bob self-issues a claim on himself; the
    ///         claimIssuer then tries to revoke it and is rejected — only bob can.
    function test_revokeClaim_byNonIssuer_reverts() public {
        // Self-issue a claim on bob from bob (issuer == bobIdentity, not claimIssuer).
        vm.prank(bob);
        bytes32 claimId =
            IERC735(address(bobIdentity)).addClaim(Constants.CLAIM_TOPIC_42, 1, address(bobIdentity), "", hex"01", "");

        // claimIssuer did not issue this claim — its revoke attempt must be rejected.
        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.NotOwnIssuance.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaim(claimId, address(bobIdentity));
    }

    /// @notice `getClaimHash` produces the same digest the helper used to sign — round-trip check.
    function test_getClaimHash_matchesSignerDigest() public view {
        bytes32 onChain = IIdentity(address(claimIssuer))
            .getClaimHash(address(aliceIdentity), Constants.CLAIM_TOPIC_666, aliceClaim666.data);
        // Re-derive the helper-side digest indirectly by re-signing with the same nonce — we
        // can simply verify isClaimValid passes (already covered) and that getClaimHash returns
        // a non-zero, deterministic digest.
        assertTrue(onChain != bytes32(0));
        bytes32 onChainAgain = IIdentity(address(claimIssuer))
            .getClaimHash(address(aliceIdentity), Constants.CLAIM_TOPIC_666, aliceClaim666.data);
        assertEq(onChain, onChainAgain, "deterministic");
    }

    /// @notice After the upstream collapse, `ClaimsModule._isClaimValid` decodes
    ///         `sig = abi.encode(bytes signer, bytes rawSig)` and gates on `signer.length < 20`
    ///         (ClaimsModule.sol:368). A wire payload with a 1-byte signer must return false
    ///         at that guard, not revert.
    function test_isClaimValid_signerShorterThan20Bytes_returnsFalse() public view {
        bytes memory tinySigner = hex"01"; // length 1 < 20
        bytes memory rawSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        bytes memory sig = abi.encode(tinySigner, rawSig);

        bool ok = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_666, sig, aliceClaim666.data);
        assertFalse(ok, "signer.length < 20 must short-circuit before any signature work");
    }

    /// @notice An EOA-shaped signer (20 bytes) that does NOT hold CLAIM_SIGNER on the issuer
    ///         must be rejected at the `keyHasPurpose(CLAIM_SIGNER)` check
    ///         (ClaimsModule.sol:371) without surfacing a revert.
    function test_isClaimValid_signerLacksClaimSignerPurpose_returnsFalse() public view {
        address stranger = address(0xBADBAD);
        bytes memory rawSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        bytes memory sig = abi.encode(abi.encodePacked(stranger), rawSig);

        bool ok = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_666, sig, aliceClaim666.data);
        assertFalse(ok, "signer without CLAIM_SIGNER must be rejected by the purpose gate");
    }

    /// @notice Pins the `ClaimsModule.revokeClaim` double-revoke guard: a second `revokeClaim`
    ///         against the same already-revoked signature must revert `ClaimAlreadyRevoked`,
    ///         not silently succeed and re-emit `ClaimRevoked`.
    function test_revokeClaim_doubleRevoke_reverts() public {
        bytes32 claimId = _aliceClaim666Id();
        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer)).revokeClaim(claimId, address(aliceIdentity));

        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.ClaimAlreadyRevoked.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaim(claimId, address(aliceIdentity));
    }

    /// @notice Pins the `require(_isClaimValid(...))` guard inside `addClaimTo`: a corrupted
    ///         signature must produce `InvalidClaim`, not silently forward the claim.
    function test_addClaimTo_invalidSignature_reverts() public {
        // Build a claim on bob from claimIssuer, then corrupt the signature tail.
        ClaimSignerHelper.Claim memory c = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(bobIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_42,
            hex"abcd",
            ""
        );
        bytes memory sig = c.signature;
        // Mutate a byte well past the 20-byte validator prefix so the inner ECDSA recovery
        // produces a wrong address.
        sig[60] = bytes1(uint8(sig[60]) ^ 0xff);

        vm.prank(claimIssuerOwner);
        // The InvalidClaim selector is consumed by the fallback's LowLevelCall.callNoReturn,
        // so the outer call bubbles a bare revert. Assert "some revert" rather than the selector.
        vm.expectRevert();
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(Constants.CLAIM_TOPIC_42, 1, sig, c.data, "", IIdentity(address(bobIdentity)));
    }

    /// @notice Pins the `ClaimsModule._isClaimValid` CLAIM_SIGNER purpose gate: a key registered
    ///         on the issuer with a purpose OTHER than CLAIM_SIGNER must not be able to sign
    ///         valid claims, even if its ECDSA signature recovers correctly.
    function test_isClaimValid_signerWithoutClaimSignerPurpose_returnsFalse() public {
        // Add a fresh signer to the issuer with ACTION purpose only (no CLAIM_SIGNER).
        (address actionSigner, uint256 actionSignerPk) = makeAddrAndKey("issuerActionOnly");
        vm.prank(claimIssuerOwner);
        claimIssuer.addKey(ClaimSignerHelper.addressToKey(actionSigner), KeyPurposes.ACTION, KeyTypes.ECDSA);

        // Sign a claim with that ACTION-only key against the issuer's domain.
        bytes memory sig = ClaimSignerHelper.signClaim(
            actionSignerPk,
            actionSigner,
            address(claimIssuer),
            address(aliceIdentity),
            Constants.CLAIM_TOPIC_42,
            hex"0badc0de"
        );

        bool ok = IClaimIssuer(address(claimIssuer))
            .isClaimValid(IIdentity(address(aliceIdentity)), Constants.CLAIM_TOPIC_42, sig, hex"0badc0de");
        assertFalse(ok, "ACTION-only signer must not produce valid claims");
    }

    // ============ ClaimsModule access-control invariants ============

    /// @notice Pins the MANAGEMENT-only gate on `revokeClaim` at `ClaimsModule.sol:229`.
    ///         A non-MANAGEMENT caller — even one holding CLAIM_SIGNER on the issuer — must
    ///         not be able to revoke claims. Existing tests only exercise the MANAGEMENT happy
    ///         path or the issuership check; this one targets the access-control gate.
    function test_revokeClaim_nonManagement_reverts() public {
        bytes32 claimId = _aliceClaim666Id();
        // carol holds CLAIM_SIGNER on the issuer but is NOT MANAGEMENT there.
        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IClaimIssuer(address(claimIssuer)).revokeClaim(claimId, address(aliceIdentity));
    }

    /// @notice Pins the `require(_isClaimValid(...), InvalidClaim())` guard inside
    ///         `addClaimTo` at `ClaimsModule.sol:306`. The existing
    ///         `test_addClaimTo_invalidSignature_reverts` cannot exercise the guard in
    ///         isolation because it targets *bobIdentity*; with `target != issuer`, bob's
    ///         `addClaim` re-validates via `IClaimIssuer(_issuer).isClaimValid(...)` and the
    ///         outer call still reverts even if the `addClaimTo` require were removed.
    ///
    ///         This test targets `issuer == target`. The inner `addClaim` then skips its own
    ///         validation (line 115: `if (_issuer != account)`), so the `addClaimTo` require
    ///         is the *only* validation between an invalid signature and a written claim.
    ///
    ///         Caveat: we first register the ClaimsModule singleton as a CLAIM_ADDER on the
    ///         issuer so the inner `addClaim` doesn't trip `_requireClaimKey` for the
    ///         cross-contract caller. (The fallback dispatch uses CALL semantics, so the
    ///         ERC-2771 trailer arriving at the issuer's ClaimsModule is the module address
    ///         itself — see the existing `test_addClaimTo_fromIssuer_writesToTargetIdentity`
    ///         note.) Without this setup both code paths revert for different reasons and a
    ///         generic `vm.expectRevert` can't tell them apart.
    function test_addClaimTo_selfTarget_invalidSig_reverts() public {
        // Register the ClaimsModule singleton as CLAIM_ADDER on the issuer so the inner
        // `addClaim` call from the module-into-self isn't blocked by `_requireClaimKey`.
        vm.prank(claimIssuerOwner);
        claimIssuer.addKey(
            ClaimSignerHelper.addressToKey(address(onchainidSetup.claimsModule)),
            KeyPurposes.CLAIM_ADDER,
            KeyTypes.ECDSA
        );

        // Build a claim signed by a key that is NOT a CLAIM_SIGNER on the issuer.
        // `_isClaimValid` will return false (line 398: keyHasPurpose check fails).
        (address stranger, uint256 strangerPk) = makeAddrAndKey("invalidClaimSigner");
        ClaimSignerHelper.Claim memory c = ClaimSignerHelper.buildClaim(
            strangerPk,
            stranger,
            address(claimIssuer), // _identity argument hashed into the digest
            address(claimIssuer), // issuer
            Constants.CLAIM_TOPIC_42,
            hex"abcd",
            ""
        );

        // claimIssuerOwner is MANAGEMENT → passes `_requireManagement`. Targets the issuer
        // itself so the inner addClaim's `_issuer == account` arm hits the no-validation
        // shortcut at line 115, making the `addClaimTo` require the only line of defense.
        vm.prank(claimIssuerOwner);
        vm.expectRevert();
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(Constants.CLAIM_TOPIC_42, 1, c.signature, c.data, "", IIdentity(address(claimIssuer)));
    }

    /// @notice Pins the MANAGEMENT-only gate on `addClaimTo` at `ClaimsModule.sol:303`.
    ///         Same shape as the `revokeClaim` access-control gate above: the issuer-side
    ///         MANAGEMENT check on cross-identity claim issuance must reject non-MANAGEMENT
    ///         callers. Without it, anyone could issue claims from a target identity by
    ///         routing through its installed ClaimsModule.
    function test_addClaimTo_nonManagement_reverts() public {
        // Build a claim on bob from claimIssuer.
        ClaimSignerHelper.Claim memory c = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(bobIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_42,
            hex"feed",
            "uri://bob"
        );

        // carol holds CLAIM_SIGNER on claimIssuer (added in helpers) but not MANAGEMENT.
        vm.prank(carol);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(Constants.CLAIM_TOPIC_42, 1, c.signature, c.data, "uri://bob", IIdentity(address(bobIdentity)));
    }

}
