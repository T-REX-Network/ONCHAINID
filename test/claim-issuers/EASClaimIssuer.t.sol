// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    IEASTest,
    ISchemaRegistryTest,
    RevocationRequest,
    RevocationRequestData
} from "../vendored/eas/EASTypes.sol";
import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
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
import { IEAS } from "contracts/vendor/eas/IEAS.sol";

/// @notice Coverage for the stateless EAS `ClaimIssuer` adapter. Each test targets one branch
///         of `isClaimValid` / `getClaimStatus` so the acceptance criteria from issue #10 map
///         1:1 to test cases.
///
/// @dev The real EAS mainnet runtime bytecode is etched at its canonical addresses so tests
///      run against the production contract, not a mock. Attestation UIDs are chosen by EAS
///      itself and captured from `attest`.
contract EASClaimIssuerTest is OnchainIDSetup {

    /// @dev Mainnet addresses. EAS embeds SchemaRegistry as an immutable, so both must be
    ///      etched at these exact addresses for `_attest` to reach the registry correctly.
    address internal constant EAS_ADDR = 0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587;
    address internal constant SCHEMA_REGISTRY_ADDR = 0xA7b39296258348C78294F95B872b282326A97BDF;

    uint64 internal constant ROLE_EAS_ADMIN = 42;

    IEASTest internal eas;
    ISchemaRegistryTest internal schemaRegistry;
    EASClaimIssuer internal adapter;

    address internal attester;

    uint256 internal constant TOPIC = 777;
    bytes32 internal SCHEMA;

    Structs.ClaimData internal emptyData;

    function setUp() public override {
        super.setUp();

        (attester,) = makeAddrAndKey("easAttester");

        // Etch mainnet EAS + SchemaRegistry so the adapter reads real bytecode.
        vm.etch(EAS_ADDR, vm.readFileBinary("test/vendored/eas/EAS.bytecode"));
        vm.etch(SCHEMA_REGISTRY_ADDR, vm.readFileBinary("test/vendored/eas/SchemaRegistry.bytecode"));
        eas = IEASTest(EAS_ADDR);
        schemaRegistry = ISchemaRegistryTest(SCHEMA_REGISTRY_ADDR);

        // Register a schema for the topic; EAS returns the schema UID.
        SCHEMA = schemaRegistry.register("bytes claimData", address(0), true);

        adapter = new EASClaimIssuer(address(onchainidSetup.accessManager), IEAS(EAS_ADDR), onchainidSetup.idFactory);

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

    /// @dev Attest under our configured SCHEMA, from the configured attester, and return the
    ///      UID EAS assigned. This replaces the previous mock's `setAttestation` shortcut.
    function _attestValid(address recipient) internal returns (bytes32) {
        return _attestAs(attester, SCHEMA, recipient, 0, hex"");
    }

    function _attestAs(address who, bytes32 schema, address recipient, uint64 expirationTime, bytes memory data)
        internal
        returns (bytes32)
    {
        AttestationRequest memory req = AttestationRequest({
            schema: schema,
            data: AttestationRequestData({
                recipient: recipient,
                expirationTime: expirationTime,
                revocable: true,
                refUID: bytes32(0),
                data: data,
                value: 0
            })
        });
        vm.prank(who);
        return eas.attest(req);
    }

    /// @dev Revoke an attestation as its attester (EAS enforces `msg.sender == attester`).
    function _revoke(bytes32 uid) internal {
        vm.prank(attester);
        eas.revoke(RevocationRequest({ schema: SCHEMA, data: RevocationRequestData({ uid: uid, value: 0 }) }));
    }

    /// @dev EIP-712 helper to build a `LinkAccount` digest for linking a wallet to an
    ///      identity. Reads the domain from the factory via EIP-5267 and hashes it via
    ///      OZ `MessageHashUtils.toDomainSeparator`, so this test never hardcodes the
    ///      factory's name, version, or field set.
    bytes32 internal constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    function _linkDigest(bytes memory account, address identity, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes32)
    {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = IERC5267(address(onchainidSetup.idFactory)).eip712Domain();

        bytes32 domain = MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt);
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
        new EASClaimIssuer(address(onchainidSetup.accessManager), IEAS(address(0)), onchainidSetup.idFactory);
    }

    function test_constructor_revertsOnZeroFactory() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new EASClaimIssuer(address(onchainidSetup.accessManager), IEAS(EAS_ADDR), IdentityFactory(address(0)));
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

    /// @notice A deployment-script bug passing an unset address must fail loudly instead of
    ///         silently writing a garbage allowlist entry.
    function test_setAttester_revertsOnZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        adapter.setAttester(address(0), true);
    }

    /* ----- isClaimValid happy paths ----- */

    function test_isClaimValid_recipientIsIdentity() public {
        bytes32 uid = _attestValid(address(aliceIdentity));

        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData);
        assertTrue(ok, "attestation on the identity itself must verify");
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Valid)
        );
    }

    function test_isClaimValid_recipientIsLinkedWallet() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = _attestValid(david);

        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData);
        assertTrue(ok, "attestation on a linked wallet must verify");
    }

    /// @notice A non-factory address that is also the EAS recipient cannot self-verify.
    ///         The self-recipient branch is gated on `isFactoryIdentity`.
    function test_isClaimValid_selfAttestationByNonFactoryIdentityRejects() public {
        address rogue = makeAddr("rogueContract");
        bytes32 uid = _attestValid(rogue);

        assertFalse(
            adapter.isClaimValid(IIdentity(rogue), TOPIC, _encodeUid(uid), emptyData),
            "non-factory identity must not self-verify"
        );
    }

    /* ----- isClaimValid rejection paths ----- */

    function test_isClaimValid_topicWithoutSchema() public {
        bytes32 uid = _attestValid(address(aliceIdentity));

        uint256 unknownTopic = 12345;
        bool ok = adapter.isClaimValid(IIdentity(address(aliceIdentity)), unknownTopic, _encodeUid(uid), emptyData);
        assertFalse(ok, "unmapped topic must reject");
    }

    function test_isClaimValid_wrongSchema() public {
        // Attest under a different schema than the one the adapter maps to TOPIC.
        bytes32 otherSchema = schemaRegistry.register("uint256 unrelated", address(0), true);
        bytes32 uid = _attestAs(attester, otherSchema, address(aliceIdentity), 0, hex"");
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_unacceptedAttester() public {
        bytes32 uid = _attestAs(bob, SCHEMA, address(aliceIdentity), 0, hex"");
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_attestationRevoked() public {
        bytes32 uid = _attestValid(address(aliceIdentity));
        _revoke(uid);

        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Revoked)
        );
    }

    function test_isClaimValid_attestationExpired() public {
        vm.warp(100);
        // Publish with a short expiry, then warp past it.
        bytes32 uid = _attestAs(attester, SCHEMA, address(aliceIdentity), uint64(block.timestamp + 10), hex"");
        vm.warp(block.timestamp + 20);

        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Expired)
        );
    }

    function test_isClaimValid_attestationExpired_atBoundary() public {
        vm.warp(100);
        // Expiry takes effect at the exact timestamp, not one block later.
        bytes32 uid = _attestAs(attester, SCHEMA, address(aliceIdentity), uint64(block.timestamp + 10), hex"");
        vm.warp(block.timestamp + 10);

        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
        assertEq(
            uint256(adapter.getClaimStatus(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData)),
            uint256(IClaimIssuer.ClaimStatus.Expired)
        );
    }

    function test_isClaimValid_attestationMissing() public view {
        // A UID that was never issued by EAS.
        bytes32 uid = keccak256("never-issued");
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    function test_isClaimValid_recipientBoundToDifferentIdentity() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = _attestValid(david);

        // Alice holds the linked wallet, so verifying against bob must reject.
        assertFalse(adapter.isClaimValid(IIdentity(address(bobIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    /// @notice The wallet-to-identity link is sticky: an attestation whose recipient is a
    ///         wallet stays valid after that wallet is revoked from the identity. The
    ///         attestation belongs to the identity, and the wallet-in-recipient is only a
    ///         resolution mechanism, so revocation of the wallet does not withdraw the
    ///         identity's eligibility. See the contract header for the recovery argument
    ///         (compromised-wallet revocation must not deadlock `isVerified` on the
    ///         identity).
    function test_isClaimValid_linkedWalletStaysValidAfterRevocation() public {
        _linkWalletToAlice(david, davidPk);
        bytes32 uid = _attestValid(david);

        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));

        // Revoking the wallet on the factory leaves the claim valid: only the wallet-as-actor
        // is disabled at the token layer, the identity's claim resolution is unchanged.
        _revokeWalletFromAlice(david);
        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData));
    }

    /// @notice A wallet that was never linked to any identity does not resolve, regardless of
    ///         whether an attestation names it.
    function test_isClaimValid_recipientWalletNeverLinkedRejects() public {
        // `david` is a fresh EOA, never linked to alice or anyone.
        bytes32 uid = _attestValid(david);
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
        bytes memory payload = abi.encode(uint256(1), "US", uint64(19900101));
        bytes32 uid = _attestAs(attester, SCHEMA, address(aliceIdentity), 0, payload);

        assertEq(adapter.getAttestationData(_encodeUid(uid)), payload);
    }

    /// @notice Missing attestation returns empty bytes rather than reverting so callers can
    ///         branch on `bytes.length == 0` without try/catch.
    function test_getAttestationData_missingAttestationReturnsEmpty() public view {
        bytes32 uid = keccak256("never-issued");
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
        bytes memory payload = hex"1234";
        bytes32 uid = _attestAs(attester, SCHEMA, address(aliceIdentity), 0, payload);
        _revoke(uid);

        assertEq(adapter.getAttestationData(_encodeUid(uid)), payload);
    }

    /* ----- full loop through ClaimsModule.addClaim ----- */

    /// @notice A holder calls the standard ERC-735 addClaim on their identity with the adapter
    ///         as issuer. The identity's ClaimsModule delegates to `adapter.isClaimValid`, which
    ///         reads EAS live and authorizes. The claim is persisted, retrievable via getClaim,
    ///         and the stored fields still verify on re-check.
    function test_fullLoop_addClaim_getClaim_reverifies() public {
        bytes32 uid = _attestValid(address(aliceIdentity));
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
        bytes32 uid = _attestValid(address(aliceIdentity));
        bytes memory sig = _encodeUid(uid);

        vm.prank(alice);
        bytes32 claimId =
            IIdentity(address(aliceIdentity)).addClaim(TOPIC, 1, address(adapter), sig, emptyData, "eas://uid");
        (,,, bytes memory sigOut, Structs.ClaimData memory dataOut,) =
            IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertTrue(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, sigOut, dataOut));

        _revoke(uid);
        assertFalse(adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, sigOut, dataOut));
    }

    /// @notice `ClaimsModule.addClaim` gates on the adapter's `isClaimValid`. When the
    ///         underlying EAS attestation does not exist, addClaim reverts with
    ///         `Errors.InvalidClaim`, so a holder cannot register a fabricated claim against
    ///         the adapter.
    function test_fullLoop_addClaim_revertsWhenAttestationMissing() public {
        bytes32 uid = keccak256("never-issued");
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

    /// @notice `isDigestRevoked` answers `false` instead of reverting so compliance call
    ///         chains (`isVerified` -> `isDigestRevoked` -> `isClaimValid`) do not abort
    ///         mid-sequence on a stateless issuer. Even for an attestation revoked on EAS
    ///         the digest read stays `false`: revocation surfaces through `isClaimValid`,
    ///         which is the source of truth.
    function test_isDigestRevoked_returnsFalse() public {
        assertFalse(adapter.isDigestRevoked(bytes32(uint256(1))));

        bytes32 uid = _attestValid(address(aliceIdentity));
        _revoke(uid);
        assertFalse(adapter.isDigestRevoked(uid), "digest read stays false even after EAS revocation");
        assertFalse(
            adapter.isClaimValid(IIdentity(address(aliceIdentity)), TOPIC, _encodeUid(uid), emptyData),
            "isClaimValid is where the revocation shows"
        );
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
