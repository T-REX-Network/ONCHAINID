// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockEAS } from "../mocks/MockEAS.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { EASClaimIssuer } from "contracts/modules/claims/EASClaimIssuer.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Attestation } from "contracts/vendor/eas/IEAS.sol";

/// @notice Coverage for the stateless EAS `ClaimIssuer` adapter. Each test targets one branch
///         of `isClaimValid` / `getClaimStatus` so the acceptance criteria from issue #10 map
///         1:1 to test cases.
contract EASClaimIssuerTest is OnchainIDSetup {

    uint64 internal constant ROLE_EAS_ADMIN = 42;

    MockEAS internal eas;
    EASClaimIssuer internal adapter;

    address internal attester;

    uint256 internal constant TOPIC = 777;
    bytes32 internal constant SCHEMA = bytes32(uint256(0xABCDEF));

    Structs.ClaimData internal emptyData;

    function setUp() public override {
        super.setUp();

        (attester,) = makeAddrAndKey("easAttester");

        eas = new MockEAS();
        adapter = new EASClaimIssuer(address(onchainidSetup.accessManager), eas, onchainidSetup.idFactory);

        // Grant the deployer permission to call the adapter's `restricted` setters.
        vm.startPrank(deployer);
        onchainidSetup.accessManager.grantRole(ROLE_EAS_ADMIN, deployer, 0);
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = EASClaimIssuer.setSchemaForTopic.selector;
        sels[1] = EASClaimIssuer.setAttester.selector;
        onchainidSetup.accessManager.setTargetFunctionRole(address(adapter), sels, ROLE_EAS_ADMIN);

        adapter.setSchemaForTopic(TOPIC, SCHEMA);
        adapter.setAttester(attester, true);
        vm.stopPrank();

        emptyData = Structs.ClaimData({ issuedAt: 0, validUntil: 0, payload: "" });
    }

    /* ----- helpers ----- */

    function _encodeUid(bytes32 uid) internal pure returns (bytes memory) {
        return abi.encodePacked(uid);
    }

    /// @dev Publish an attestation the adapter will accept as Valid before the recipient check.
    function _publishValid(bytes32 uid, address recipient) internal {
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: SCHEMA,
                time: uint64(block.timestamp),
                expirationTime: 0,
                revocationTime: 0,
                refUID: bytes32(0),
                recipient: recipient,
                attester: attester,
                revocable: true,
                data: hex""
            })
        );
    }

    /// @dev EIP-712 helpers to link a wallet to alice's identity, mirroring the pattern used
    ///      in IdentityFactory.t.sol.
    bytes32 internal constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    function _linkDigest(bytes memory account, address identity, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes32)
    {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IdentityFactory")),
                keccak256(bytes("1")),
                block.chainid,
                address(onchainidSetup.idFactory)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), identity, nonce, expiry));
        return MessageHashUtils.toTypedDataHash(domain, structHash);
    }

    function _linkWalletToAlice(address wallet, uint256 walletPk) internal {
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, wallet);
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(envelope);
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 digest = _linkDigest(envelope, address(aliceIdentity), nonce, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes memory call = abi.encodeCall(IIdentityFactory.linkAccount, (envelope, sig, nonce, expiry));
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).execute(address(onchainidSetup.idFactory), 0, call);
    }

    function _revokeWalletFromAlice(address wallet) internal {
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, wallet);
        bytes memory call = abi.encodeCall(IIdentityFactory.revokeAccount, (envelope));
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).execute(address(onchainidSetup.idFactory), 0, call);
    }

    /* ----- constructor guards ----- */

    function test_constructor_revertsOnZeroEAS() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new EASClaimIssuer(address(onchainidSetup.accessManager), MockEAS(address(0)), onchainidSetup.idFactory);
    }

    function test_constructor_revertsOnZeroFactory() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new EASClaimIssuer(address(onchainidSetup.accessManager), eas, IdentityFactory(address(0)));
    }

    /* ----- admin setters ----- */

    function test_setSchema_revertsWithoutRole() public {
        vm.prank(bob);
        vm.expectRevert();
        adapter.setSchemaForTopic(TOPIC, SCHEMA);
    }

    function test_setAttester_revertsWithoutRole() public {
        vm.prank(bob);
        vm.expectRevert();
        adapter.setAttester(attester, true);
    }

    /* ----- isClaimValid happy paths ----- */

    function test_isClaimValid_recipientIsIdentity() public {
        bytes32 uid = keccak256("id-recipient");
        _publishValid(uid, address(aliceIdentity));

        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData);
        assertTrue(ok, "attestation on the identity itself must verify");
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Valid)
        );
    }

    function test_isClaimValid_recipientIsLinkedWallet() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = keccak256("linked-wallet");
        _publishValid(uid, david);

        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData);
        assertTrue(ok, "attestation on a linked wallet must verify");
    }

    /// @notice A non-factory address that is also the EAS recipient cannot self-verify.
    ///         The self-recipient branch is gated on `isFactoryIdentity`.
    function test_isClaimValid_selfAttestationByNonFactoryIdentityRejects() public {
        address rogue = makeAddr("rogueContract");
        bytes32 uid = keccak256("rogue-self-attest");
        _publishValid(uid, rogue);

        assertFalse(
            adapter.isClaimValid(IIdentity(rogue), TOPIC, _encodeUid(uid), emptyData),
            "non-factory identity must not self-verify"
        );
    }

    /* ----- isClaimValid rejection paths ----- */

    function test_isClaimValid_topicWithoutSchema() public {
        bytes32 uid = keccak256("no-schema");
        _publishValid(uid, address(aliceIdentity));

        uint256 unknownTopic = 12345;
        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), unknownTopic, _encodeUid(uid), emptyData);
        assertFalse(ok, "unmapped topic must reject");
    }

    function test_isClaimValid_wrongSchema() public {
        bytes32 uid = keccak256("wrong-schema");
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: bytes32(uint256(0x99)),
                time: uint64(block.timestamp),
                expirationTime: 0,
                revocationTime: 0,
                refUID: bytes32(0),
                recipient: address(aliceIdentity),
                attester: attester,
                revocable: true,
                data: hex""
            })
        );
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_unacceptedAttester() public {
        bytes32 uid = keccak256("wrong-attester");
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: SCHEMA,
                time: uint64(block.timestamp),
                expirationTime: 0,
                revocationTime: 0,
                refUID: bytes32(0),
                recipient: address(aliceIdentity),
                attester: bob,
                revocable: true,
                data: hex""
            })
        );
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_attestationRevoked() public {
        bytes32 uid = keccak256("revoked");
        _publishValid(uid, address(aliceIdentity));
        eas.revoke(uid, uint64(block.timestamp));

        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Revoked)
        );
    }

    function test_isClaimValid_attestationExpired() public {
        vm.warp(100);
        bytes32 uid = keccak256("expired");
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: SCHEMA,
                time: uint64(block.timestamp - 10),
                expirationTime: uint64(block.timestamp - 1),
                revocationTime: 0,
                refUID: bytes32(0),
                recipient: address(aliceIdentity),
                attester: attester,
                revocable: true,
                data: hex""
            })
        );
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Expired)
        );
    }

    function test_isClaimValid_attestationMissing() public view {
        bytes32 uid = keccak256("missing");
        // Never publish `uid`.
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_recipientBoundToDifferentIdentity() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = keccak256("wrong-holder");
        _publishValid(uid, david);

        // Alice holds the linked wallet, so verifying against bob must reject.
        assertFalse(adapter.isClaimValid(IIdentity(address(bobIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_linkedWalletThenRevoked_rejects() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = keccak256("wallet-then-revoked");
        _publishValid(uid, david);

        // Verifies while active.
        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));

        // After factory-side revocation the adapter must return false. The EAS attestation is
        // still live but the recipient wallet no longer authenticates.
        _revokeWalletFromAlice(david);
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    /* ----- signature payload sanity ----- */

    function test_isClaimValid_shortSignatureBytes() public view {
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, hex"deadbeef", emptyData)),
            uint256(IClaimIssuer.ClaimStatus.BadSignature)
        );
    }

    function test_isClaimValid_zeroUidBytes() public view {
        bytes memory sig = new bytes(32);
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, sig, emptyData)),
            uint256(IClaimIssuer.ClaimStatus.BadSignature)
        );
    }

    /* ----- getAttestationData ----- */

    /// @notice The raw attestation payload round-trips through the adapter.
    function test_getAttestationData_returnsPayload() public {
        bytes32 uid = keccak256("payload");
        bytes memory payload = abi.encode(uint256(1), "US", uint64(19900101));
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: SCHEMA,
                time: uint64(block.timestamp),
                expirationTime: 0,
                revocationTime: 0,
                refUID: bytes32(0),
                recipient: address(aliceIdentity),
                attester: attester,
                revocable: true,
                data: payload
            })
        );

        assertEq(adapter.getAttestationData(_encodeUid(uid)), payload);
    }

    /// @notice Missing attestation returns empty bytes rather than reverting so callers can
    ///         branch on `bytes.length == 0` without try/catch.
    function test_getAttestationData_missingAttestationReturnsEmpty() public view {
        bytes32 uid = keccak256("never-published");
        assertEq(adapter.getAttestationData(_encodeUid(uid)).length, 0);
    }

    /// @notice Malformed sig (not 32 bytes) also returns empty rather than reverting.
    function test_getAttestationData_shortSignatureReturnsEmpty() public view {
        assertEq(adapter.getAttestationData(hex"deadbeef").length, 0);
    }

    /// @notice `getAttestationData` is a raw read: it does NOT re-check schema, attester, or
    ///         revocation. A revoked attestation still returns its payload; the caller should
    ///         pair with `getClaimStatus` when validity matters.
    function test_getAttestationData_returnsPayloadEvenWhenRevoked() public {
        bytes32 uid = keccak256("revoked-but-readable");
        bytes memory payload = hex"1234";
        eas.setAttestation(
            Attestation({
                uid: uid,
                schema: SCHEMA,
                time: uint64(block.timestamp),
                expirationTime: 0,
                revocationTime: uint64(block.timestamp),
                refUID: bytes32(0),
                recipient: address(aliceIdentity),
                attester: attester,
                revocable: true,
                data: payload
            })
        );

        assertEq(adapter.getAttestationData(_encodeUid(uid)), payload);
    }

    /* ----- full loop through ClaimsModule.addClaim ----- */

    /// @notice A holder calls the standard ERC-735 addClaim on their identity with the adapter
    ///         as issuer. The identity's ClaimsModule delegates to `adapter.isClaimValid`, which
    ///         reads EAS live and authorizes. The claim is persisted, retrievable via getClaim,
    ///         and the stored fields still verify on re-check.
    function test_fullLoop_addClaim_getClaim_reverifies() public {
        bytes32 uid = keccak256("full-loop");
        _publishValid(uid, address(aliceIdentity));

        bytes memory sig = _encodeUid(uid);

        vm.prank(alice);
        bytes32 claimId =
            IIdentity(address(aliceIdentity)).addClaim(TOPIC, 1, address(adapter), sig, emptyData, "eas://uid");

        assertEq(claimId, keccak256(abi.encode(address(adapter), TOPIC)));

        (uint256 topic_, uint256 scheme_, address issuer_, bytes memory sigOut, Structs.ClaimData memory dataOut,) =
            IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic_, TOPIC);
        assertEq(scheme_, 1);
        assertEq(issuer_, address(adapter));

        // Downstream `isVerified` callers read the stored fields back and re-invoke
        // `isClaimValid`, so the re-check must stay Valid.
        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), topic_, sigOut, dataOut));
    }

    /// @notice After a successful addClaim, revoking on EAS flips the stored claim's
    ///         verification result to false without any on-chain claim mutation on the holder.
    function test_fullLoop_easRevocationFlipsStoredClaim() public {
        bytes32 uid = keccak256("full-loop-revoke");
        _publishValid(uid, address(aliceIdentity));
        bytes memory sig = _encodeUid(uid);

        vm.prank(alice);
        bytes32 claimId =
            IIdentity(address(aliceIdentity)).addClaim(TOPIC, 1, address(adapter), sig, emptyData, "eas://uid");
        (,,, bytes memory sigOut, Structs.ClaimData memory dataOut,) =
            IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, sigOut, dataOut));

        eas.revoke(uid, uint64(block.timestamp));
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, sigOut, dataOut));
    }

    /// @notice `ClaimsModule.addClaim` gates on the adapter's `isClaimValid`. When the
    ///         underlying EAS attestation does not exist, addClaim reverts with
    ///         `Errors.InvalidClaim`, so a holder cannot register a fabricated claim against
    ///         the adapter.
    function test_fullLoop_addClaim_revertsWhenAttestationMissing() public {
        bytes32 uid = keccak256("never-published");
        bytes memory sig = _encodeUid(uid);

        vm.prank(alice);
        vm.expectRevert(Errors.InvalidClaim.selector);
        IIdentity(address(aliceIdentity)).addClaim(TOPIC, 1, address(adapter), sig, emptyData, "");
    }

    /* ----- unsupported surface ----- */

    function test_revokeClaimByDigest_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.revokeClaimByDigest(bytes32(uint256(1)));
    }

    function test_isDigestRevoked_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.isDigestRevoked(bytes32(uint256(1)));
    }

    function test_addClaimTo_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.addClaimTo(TOPIC, 1, hex"", emptyData, "", IIdentity(address(aliceIdentity)));
    }

    function test_addKey_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.addKey(bytes32(uint256(1)), 1, 1);
    }

    function test_getIdentityType_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.getIdentityType();
    }

    function test_addClaim_reverts() public {
        vm.expectRevert(Errors.EASNotSupported.selector);
        adapter.addClaim(TOPIC, 1, address(this), hex"", emptyData, "");
    }

}
