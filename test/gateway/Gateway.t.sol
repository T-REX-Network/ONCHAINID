// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { IdentityHelper } from "../helpers/IdentityHelper.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Identity } from "contracts/Identity.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { Gateway } from "contracts/gateway/Gateway.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Test } from "forge-std/Test.sol";

contract GatewayTest is Test {

    IdentityHelper.OnchainIDSetup internal setup;

    address internal deployer;
    uint256 internal deployerPk;
    address internal alice;
    uint256 internal alicePk;
    address internal bob;
    uint256 internal bobPk;
    address internal carol;
    uint256 internal carolPk;

    Structs.ModuleInstall[] internal _emptyModules;

    function setUp() public {
        (deployer, deployerPk) = makeAddrAndKey("gwDeployer");
        (alice, alicePk) = makeAddrAndKey("gwAlice");
        (bob, bobPk) = makeAddrAndKey("gwBob");
        (carol, carolPk) = makeAddrAndKey("gwCarol");

        vm.warp(365 days);

        vm.startPrank(deployer);
        setup = IdentityHelper.deployFactory(deployer);
        vm.stopPrank();
    }

    // ---- helpers ----

    function _makeECDSAKey(address addr, uint256 purpose) internal pure returns (Structs.KeyParam memory) {
        return Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(addr)),
            purpose: purpose,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(addr),
            clientData: ""
        });
    }

    function _makeSingleMgmtKeys(address addr) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(addr, KeyPurposes.MANAGEMENT);
    }

    bytes32 internal constant _DEPLOY_TYPEHASH = keccak256(
        "Deploy(address identityOwner,uint256 identityType,string salt,KeyParam[] keys,ModuleInstall[] modules,uint256 signatureExpiry)KeyParam(bytes32 keyHash,uint256 purpose,uint256 keyType,bytes signerData,bytes clientData)ModuleInstall(uint256 moduleType,address module,bytes initData)"
    );

    bytes32 internal constant _KEY_PARAM_TYPEHASH =
        keccak256("KeyParam(bytes32 keyHash,uint256 purpose,uint256 keyType,bytes signerData,bytes clientData)");

    function _signDeploy(
        Gateway gateway_,
        uint256 signerPk,
        address owner,
        string memory salt,
        Structs.KeyParam[] memory keys,
        uint256 identityType,
        uint256 expiry
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                _DEPLOY_TYPEHASH,
                owner,
                identityType,
                keccak256(bytes(salt)),
                _hashKeyParams(keys),
                keccak256(""), // empty modules array
                expiry
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", gateway_.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashKeyParams(Structs.KeyParam[] memory keys) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    _KEY_PARAM_TYPEHASH,
                    keys[i].keyHash,
                    keys[i].purpose,
                    keys[i].keyType,
                    keccak256(keys[i].signerData),
                    keccak256(keys[i].clientData)
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _deployGateway(address[] memory signers) internal returns (Gateway) {
        // The test contract is the owner so owner-gated functions can be invoked directly
        // by the test body without `vm.prank(...)` boilerplate.
        return new Gateway(address(setup.idFactory), signers, address(this));
    }

    function _deployGatewayWithCarol() internal returns (Gateway) {
        address[] memory signers = new address[](1);
        signers[0] = carol;
        return _deployGateway(signers);
    }

    /// @dev Recurring 3-line setup: deploy gateway with carol as the only signer AND transfer
    ///      the factory ownership to it so deployment paths work. Used by ~25 tests; the
    ///      ~12 tests that exercise gateway-only behavior (no factory call) keep using
    ///      `_deployGatewayWithCarol()` to avoid taking factory ownership unnecessarily.
    function _deployGatewayOwnedByCarol() internal returns (Gateway gateway) {
        gateway = _deployGatewayWithCarol();
        vm.prank(deployer);
        setup.idFactory.transferOwnership(address(gateway));
    }

    /// @dev Recurring 5-line scaffold used by every "deploy + sign with carol against alice's
    ///      management key + 365-day expiry" test: bundles `_deployGatewayOwnedByCarol`,
    ///      `_makeSingleMgmtKeys(alice)`, a 365-day expiry, and a carol-signed deploy digest.
    ///      Used by ~11 deploy / tampering / revoke-then-deploy tests. Tests with non-365
    ///      expiry or non-alice management still build the pieces inline.
    function _deployedAndSigned(string memory salt)
        internal
        returns (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig)
    {
        gateway = _deployGatewayOwnedByCarol();
        keys = _makeSingleMgmtKeys(alice);
        expiry = block.timestamp + 365 days;
        sig = _signDeploy(gateway, carolPk, alice, salt, keys, IdentityTypes.INDIVIDUAL, expiry);
    }

    // ============ constructor ============

    function test_constructor_revertZeroFactory() public {
        address[] memory signers = new address[](0);
        vm.expectRevert(Errors.ZeroAddress.selector);
        new Gateway(address(0), signers, deployer);
    }

    function test_constructor_revertTooManySigners() public {
        address[] memory signers = new address[](11);
        vm.expectRevert(Errors.TooManySigners.selector);
        new Gateway(address(setup.idFactory), signers, deployer);
    }

    // ============ deployIdentityWithSalt ============

    function test_deployIdentityWithSalt_revertZeroAddress() public {
        Gateway gateway = _deployGatewayWithCarol();
        bytes memory sig = new bytes(65);

        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.deployIdentityWithSalt(
            address(0),
            IdentityTypes.INDIVIDUAL,
            "saltToUse",
            _makeSingleMgmtKeys(address(0)),
            _emptyModules,
            block.timestamp + 365 days,
            sig
        );
    }

    function test_deployIdentityWithSalt_revertInvalidSignature() public {
        Gateway gateway = _deployGatewayWithCarol();
        bytes memory sig = new bytes(65);

        vm.expectRevert();
        gateway.deployIdentityWithSalt(
            alice,
            IdentityTypes.INDIVIDUAL,
            "saltToUse",
            _makeSingleMgmtKeys(alice),
            _emptyModules,
            block.timestamp + 365 days,
            sig
        );
    }

    function test_deployIdentityWithSalt_revertUnapprovedSigner() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, bobPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        vm.expectRevert(abi.encodeWithSelector(Errors.UnapprovedSigner.selector, bob));
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltToUse", keys, _emptyModules, expiry, sig);
    }

    function test_deployIdentityWithSalt_shouldDeploy() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("saltToUse");
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltToUse", keys, _emptyModules, expiry, sig);

        address identityAddr = setup.idFactory.getIdentity(alice);
        assertTrue(identityAddr != address(0));
        assertTrue(
            Identity(payable(identityAddr)).keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT)
        );
    }

    function test_deployIdentityWithSalt_withMultipleKeys() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        address claimAdder = makeAddr("gwClaimAdder");
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](2);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);
        keys[1] = _makeECDSAKey(claimAdder, KeyPurposes.CLAIM_ADDER);

        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltWithKeys", keys, IdentityTypes.INDIVIDUAL, expiry);
        gateway.deployIdentityWithSalt(
            alice, IdentityTypes.INDIVIDUAL, "saltWithKeys", keys, _emptyModules, expiry, sig
        );

        address identityAddr = setup.idFactory.getIdentity(alice);
        Identity identity = Identity(payable(identityAddr));
        assertTrue(identity.keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT));
        assertTrue(identity.keyHasPurpose(ClaimSignerHelper.addressToKey(claimAdder), KeyPurposes.CLAIM_ADDER));
    }

    function test_deployIdentityWithSalt_withCustomManagementKeys() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        // bob as management key, not alice
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(bob);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltCustom", keys, IdentityTypes.INDIVIDUAL, expiry);
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltCustom", keys, _emptyModules, expiry, sig);

        address identityAddr = setup.idFactory.getIdentity(alice);
        Identity identity = Identity(payable(identityAddr));
        assertFalse(identity.keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT));
        assertTrue(identity.keyHasPurpose(ClaimSignerHelper.addressToKey(bob), KeyPurposes.MANAGEMENT));
    }

    function test_deployIdentityWithSalt_noExpiry() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, 0);
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltToUse", keys, _emptyModules, 0, sig);

        assertTrue(setup.idFactory.getIdentity(alice) != address(0));
    }

    function test_deployIdentityWithSalt_revertRevokedSignature() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("saltToUse");

        gateway.revokeSignature(sig);

        vm.expectRevert(abi.encodeWithSelector(Errors.RevokedSignature.selector, sig));
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltToUse", keys, _emptyModules, expiry, sig);
    }

    function test_deployIdentityWithSalt_revertExpiredSignature() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp - 2 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        vm.expectRevert(abi.encodeWithSelector(Errors.ExpiredSignature.selector, sig));
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "saltToUse", keys, _emptyModules, expiry, sig);
    }

    // ============ deployIdentityForWallet ============

    function test_deployForWallet_revertZeroAddress() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.deployIdentityForWallet(
            address(0), IdentityTypes.INDIVIDUAL, _makeSingleMgmtKeys(address(0)), _emptyModules
        );
    }

    function test_deployForWallet_anotherSender() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        vm.prank(bob);
        gateway.deployIdentityForWallet(alice, IdentityTypes.INDIVIDUAL, _makeSingleMgmtKeys(alice), _emptyModules);

        address identityAddr = setup.idFactory.getIdentity(alice);
        assertTrue(identityAddr != address(0));
        assertTrue(
            Identity(payable(identityAddr)).keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT)
        );
    }

    function test_deployForWallet_shouldDeploy() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        vm.prank(alice);
        gateway.deployIdentityForWallet(alice, IdentityTypes.INDIVIDUAL, _makeSingleMgmtKeys(alice), _emptyModules);

        assertTrue(setup.idFactory.getIdentity(alice) != address(0));
    }

    function test_deployForWallet_revertAlreadyDeployed() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        vm.prank(alice);
        gateway.deployIdentityForWallet(alice, IdentityTypes.INDIVIDUAL, _makeSingleMgmtKeys(alice), _emptyModules);

        vm.prank(alice);
        vm.expectRevert();
        gateway.deployIdentityForWallet(alice, IdentityTypes.INDIVIDUAL, _makeSingleMgmtKeys(alice), _emptyModules);
    }

    // ============ transferFactoryOwnership ============

    function test_transferOwnership_shouldTransfer() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        gateway.transferFactoryOwnership(bob);
        assertEq(setup.idFactory.owner(), bob);
    }

    function test_transferOwnership_revertNotOwner() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.transferFactoryOwnership(bob);
    }

    // ============ revokeSignature ============

    function test_revokeSignature_revertNotOwner() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.revokeSignature(sig);
    }

    function test_revokeSignature_revertAlreadyRevoked() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        gateway.revokeSignature(sig);

        vm.expectRevert(abi.encodeWithSelector(Errors.SignatureAlreadyRevoked.selector, sig));
        gateway.revokeSignature(sig);
    }

    // ============ approveSignature ============

    function test_approveSignature_revertNotOwner() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.approveSignature(sig);
    }

    function test_approveSignature_revertNotRevoked() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        vm.expectRevert(abi.encodeWithSelector(Errors.SignatureNotRevoked.selector, sig));
        gateway.approveSignature(sig);
    }

    function test_approveSignature_shouldApprove() public {
        Gateway gateway = _deployGatewayWithCarol();
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp + 365 days;
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "saltToUse", keys, IdentityTypes.INDIVIDUAL, expiry);

        gateway.revokeSignature(sig);
        gateway.approveSignature(sig);
    }

    // ============ approveSigner ============

    function test_approveSigner_revertZeroAddress() public {
        Gateway gateway = _deployGatewayWithCarol();
        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.approveSigner(address(0));
    }

    function test_approveSigner_revertNotOwner() public {
        Gateway gateway = _deployGatewayWithCarol();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.approveSigner(bob);
    }

    function test_approveSigner_revertAlreadyApproved() public {
        Gateway gateway = _deployGatewayWithCarol();
        gateway.approveSigner(bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.SignerAlreadyApproved.selector, bob));
        gateway.approveSigner(bob);
    }

    function test_approveSigner_shouldApprove() public {
        Gateway gateway = _deployGatewayWithCarol();
        gateway.approveSigner(bob);
        assertTrue(gateway.approvedSigners(bob));
    }

    // ============ revokeSigner ============

    function test_revokeSigner_revertZeroAddress() public {
        address[] memory signers = new address[](1);
        signers[0] = alice;
        Gateway gateway = _deployGateway(signers);
        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.revokeSigner(address(0));
    }

    function test_revokeSigner_revertNotOwner() public {
        address[] memory signers = new address[](1);
        signers[0] = bob;
        Gateway gateway = _deployGateway(signers);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.revokeSigner(bob);
    }

    function test_revokeSigner_revertNotApproved() public {
        address[] memory signers = new address[](1);
        signers[0] = alice;
        Gateway gateway = _deployGateway(signers);
        vm.expectRevert(abi.encodeWithSelector(Errors.SignerAlreadyNotApproved.selector, bob));
        gateway.revokeSigner(bob);
    }

    function test_revokeSigner_shouldRevoke() public {
        address[] memory signers = new address[](1);
        signers[0] = bob;
        Gateway gateway = _deployGateway(signers);
        gateway.revokeSigner(bob);
        assertFalse(gateway.approvedSigners(bob));
    }

    // ============ callFactory ============

    function test_callFactory_revertNotOwner() public {
        address[] memory signers = new address[](1);
        signers[0] = alice;
        Gateway gateway = _deployGateway(signers);
        vm.prank(deployer);
        setup.idFactory.transferOwnership(address(gateway));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        gateway.callFactory(abi.encodeCall(IdFactory.addTokenFactory, (address(0))));
    }

    function test_callFactory_revertFactoryError() public {
        address[] memory signers = new address[](1);
        signers[0] = alice;
        Gateway gateway = _deployGateway(signers);
        vm.prank(deployer);
        setup.idFactory.transferOwnership(address(gateway));

        vm.expectRevert(Errors.CallToFactoryFailed.selector);
        gateway.callFactory(abi.encodeCall(IdFactory.addTokenFactory, (address(0))));
    }

    function test_callFactory_shouldExecute() public {
        address[] memory signers = new address[](1);
        signers[0] = alice;
        Gateway gateway = _deployGateway(signers);
        vm.prank(deployer);
        setup.idFactory.transferOwnership(address(gateway));

        gateway.callFactory(abi.encodeCall(IdFactory.addTokenFactory, (bob)));
        assertTrue(setup.idFactory.isTokenFactory(bob));
    }

    // ============ Constructor edge arms ============

    /// @notice Constructor with an empty signer list — the for-loop body never executes.
    function test_constructor_emptySignerList_deploysWithoutSigners() public {
        address[] memory signers = new address[](0);
        Gateway gw = new Gateway(address(setup.idFactory), signers, address(this));
        assertFalse(gw.approvedSigners(carol));
        assertFalse(gw.approvedSigners(address(this)));
    }

    /// @notice Constructor with multiple signers loops `signersToApprove.length` times.
    ///         Covers the i>0 iteration that single-signer tests miss.
    function test_constructor_multipleSigners_allApproved() public {
        address[] memory signers = new address[](3);
        signers[0] = alice;
        signers[1] = bob;
        signers[2] = carol;
        Gateway gw = new Gateway(address(setup.idFactory), signers, address(this));
        assertTrue(gw.approvedSigners(alice));
        assertTrue(gw.approvedSigners(bob));
        assertTrue(gw.approvedSigners(carol));
    }

    // ============ domainSeparator accessor ============

    function test_domainSeparator_returnsNonZero() public {
        Gateway gw = _deployGatewayWithCarol();
        assertTrue(gw.domainSeparator() != bytes32(0), "domainSeparator must not be zero");
    }

    // ============ revokeSignature happy path + downstream deployment fail ============

    /// @notice Revoking a signature succeeds when it has not been revoked before; subsequent
    ///         `deployIdentityWithSalt` calls using that signature MUST trip the RevokedSignature
    ///         arm at Gateway.sol:141.
    function test_revokeSignature_thenDeploy_revertsRevokedSignature() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("revoked-then-deploy");

        // Revoke succeeds (happy path).
        gateway.revokeSignature(sig);
        assertTrue(gateway.revokedSignatures(sig));

        // Now try to use the revoked signature — must fail with RevokedSignature.
        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert(abi.encodeWithSelector(Errors.RevokedSignature.selector, sig));
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "revoked-then-deploy", keys, mods, expiry, sig);
    }

    // ============ signer revoked between signing and deployment ============

    /// @notice A signature produced by an approved signer must fail after that signer has been
    ///         revoked via `revokeSigner`. Exercises the `!approvedSigners[signer]` arm at
    ///         Gateway.sol:140 with a recovered signer whose state changed mid-flight.
    function test_signerRevokedBetweenSigAndCall_revertsUnapprovedSigner() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("signer-revoked");

        // Revoke carol's approval after the signature is produced but before deployment runs.
        gateway.revokeSigner(carol);

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert(abi.encodeWithSelector(Errors.UnapprovedSigner.selector, carol));
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "signer-revoked", keys, mods, expiry, sig);
    }

    // ============ signature tampering detection ============
    //
    // The Gateway recovers the signer from an EIP-712 digest computed over the deployment
    // payload (identityType, salt, expiry, owner, keys). If any field is altered between
    // signing and submission, `ecrecover` returns a different address than the original
    // signer. The recovered address is then either an attacker-controlled value (rare) or
    // a junk address (typical) — neither is in the `approvedSigners` set, so the call
    // reverts `UnapprovedSigner`. The five tests below pin this property for each signed
    // field individually.

    /// @notice Tampering with `identityType` after signing yields a different ECDSA-recovered
    ///         address; that address isn't in the approvedSigners set → UnapprovedSigner.
    function test_tampering_identityType_recoversWrongSigner() public {
        // Signed against IdentityTypes.INDIVIDUAL; the test submits CLAIM_ISSUER instead.
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("tamper-type");

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert(); // UnapprovedSigner with whatever wrong address ecrecover returns.
        gateway.deployIdentityWithSalt(alice, IdentityTypes.CLAIM_ISSUER, "tamper-type", keys, mods, expiry, sig);
    }

    /// @notice Tampering with the `salt` field changes the EIP-712 digest, so ECDSA recovery
    ///         yields a different signer → UnapprovedSigner.
    function test_tampering_salt_recoversWrongSigner() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("salt-a");

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert();
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "salt-b", keys, mods, expiry, sig);
    }

    /// @notice Tampering with the `signatureExpiry` field changes the EIP-712 digest, so
    ///         ECDSA recovery yields a different signer → UnapprovedSigner.
    function test_tampering_expiry_recoversWrongSigner() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("exp-tamper");

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert();
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "exp-tamper", keys, mods, expiry + 1, sig);
    }

    /// @notice Tampering with the `identityOwner` field changes the EIP-712 digest, so
    ///         ECDSA recovery yields a different signer → UnapprovedSigner.
    function test_tampering_owner_recoversWrongSigner() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("owner-tamper");

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert();
        gateway.deployIdentityWithSalt(bob, IdentityTypes.INDIVIDUAL, "owner-tamper", keys, mods, expiry, sig);
    }

    /// @notice Tampering with the keys array changes the EIP-712 digest, so ECDSA recovery
    ///         yields a different signer → UnapprovedSigner.
    function test_tampering_keys_recoversWrongSigner() public {
        (Gateway gateway, Structs.KeyParam[] memory signedKeys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("keys-tamper");

        // Submit a different keys array (extra key) — keys hash changes, recovery differs.
        Structs.KeyParam[] memory submittedKeys = new Structs.KeyParam[](2);
        submittedKeys[0] = signedKeys[0];
        submittedKeys[1] = _makeECDSAKey(bob, KeyPurposes.MANAGEMENT);

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        vm.expectRevert();
        gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "keys-tamper", submittedKeys, mods, expiry, sig);
    }

    // ============ Signature exactly at expiry boundary — `block.timestamp == expiry` accepted ============

    /// @notice The expiry check is `block.timestamp <= signatureExpiry` — at the boundary the
    ///         call must still succeed. Existing `revertExpiredSignature` covers the t > expiry
    ///         arm; this is the t == expiry arm.
    function test_expiry_atBoundary_accepted() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        uint256 expiry = block.timestamp; // exactly at boundary
        bytes memory sig = _signDeploy(gateway, carolPk, alice, "boundary", keys, IdentityTypes.INDIVIDUAL, expiry);

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        address id =
            gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "boundary", keys, mods, expiry, sig);
        assertTrue(id != address(0));
    }

    // ============ Behavior invariants ============

    /// @notice Complements `test_approveSignature_shouldApprove` (which only checks the
    ///         call doesn't revert) with the end-to-end round-trip: revoke a signature,
    ///         approve it back, and assert it's usable for a fresh `deployIdentityWithSalt`.
    ///         This pins the `delete revokedSignatures[signature]` write so an "un-revoked"
    ///         signature actually returns to the usable state, not just the event log.
    function test_approveSignature_clearsRevokedFlag() public {
        (Gateway gateway, Structs.KeyParam[] memory keys, uint256 expiry, bytes memory sig) =
            _deployedAndSigned("revoke-then-approve");

        gateway.revokeSignature(sig);
        assertTrue(gateway.revokedSignatures(sig), "must be revoked after revokeSignature");

        gateway.approveSignature(sig);
        assertFalse(gateway.revokedSignatures(sig), "approveSignature MUST clear the revoked flag");

        // End-to-end: the un-revoked sig must now be usable for a deployment.
        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        address id = gateway.deployIdentityWithSalt(
            alice, IdentityTypes.INDIVIDUAL, "revoke-then-approve", keys, mods, expiry, sig
        );
        assertTrue(id != address(0), "deployment must succeed after un-revoke");
    }

    /// @notice Pins the Gateway-level zero-address check in `deployIdentityForWallet` at
    ///         `Gateway.sol:198`. Existing `test_deployForWallet_revertZeroAddress` cannot
    ///         exercise the gate in isolation: the downstream `IdFactory.createIdentity` ALSO
    ///         reverts with `ZeroAddress`, so even if the Gateway-level check were absent the
    ///         call would still appear to revert with the expected selector.
    ///
    ///         The trick: deploy the Gateway WITHOUT giving it factory ownership. The
    ///         factory's `onlyOwner` modifier then fires before the factory's zero-address
    ///         check, producing `OwnableUnauthorizedAccount`. So the Gateway-level check is
    ///         the only path that yields `ZeroAddress` — asserting it confirms the gate fires
    ///         before delegation.
    function test_deployForWallet_zeroAddress_shortCircuitsBeforeFactory() public {
        Gateway gateway = _deployGatewayWithCarol();
        // Note: intentionally do NOT transfer factory ownership.

        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](0);
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);

        vm.expectRevert(Errors.ZeroAddress.selector);
        gateway.deployIdentityForWallet(address(0), IdentityTypes.INDIVIDUAL, keys, mods);
    }

    /// @notice Pins the `_hashModuleInstalls` for-loop at `Gateway.sol:172`. Every other
    ///         Gateway test uses an empty modules array, so the loop body is never reached
    ///         and any regression in its bounds, step direction, or termination would go
    ///         undetected. This test signs and submits a deployment with a non-empty modules
    ///         list, exercising the loop end-to-end: if on-chain hashing diverges from
    ///         off-chain hashing the recovered signer is wrong → `UnapprovedSigner` revert.
    function test_deployIdentityWithSalt_withNonEmptyModules_signerRecoversCorrectly() public {
        Gateway gateway = _deployGatewayOwnedByCarol();

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(alice);
        Structs.ModuleInstall[] memory mods = new Structs.ModuleInstall[](1);
        mods[0] = Structs.ModuleInstall({
            moduleType: 1, // MODULE_TYPE_VALIDATOR
            module: address(setup.signatureValidator),
            initData: "",
            purpose: 0
        });

        uint256 expiry = block.timestamp + 1 days;
        bytes memory sig =
            _signWithModules(gateway, carolPk, alice, "nonempty-mods", keys, mods, IdentityTypes.INDIVIDUAL, expiry);

        address id =
            gateway.deployIdentityWithSalt(alice, IdentityTypes.INDIVIDUAL, "nonempty-mods", keys, mods, expiry, sig);
        assertTrue(id != address(0));
    }

    // ============ Helpers exclusive to the non-empty-modules signer path ============

    bytes32 internal constant _MODULE_INSTALL_TYPEHASH =
        keccak256("ModuleInstall(uint256 moduleType,address module,bytes initData)");

    /// @dev EIP-712 signer for `Deploy` with a non-empty modules array. Generalizes `_signDeploy`
    ///      (which always hashes the empty-modules sentinel) by threading the modules through
    ///      `_hashModuleInstalls` so the off-chain digest matches the on-chain one.
    function _signWithModules(
        Gateway gateway_,
        uint256 signerPk,
        address owner,
        string memory salt,
        Structs.KeyParam[] memory keys,
        Structs.ModuleInstall[] memory mods,
        uint256 identityType,
        uint256 expiry
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                _DEPLOY_TYPEHASH,
                owner,
                identityType,
                keccak256(bytes(salt)),
                _hashKeyParams(keys),
                _hashModuleInstalls(mods),
                expiry
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", gateway_.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashModuleInstalls(Structs.ModuleInstall[] memory mods) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](mods.length);
        for (uint256 i = 0; i < mods.length; i++) {
            hashes[i] = keccak256(
                abi.encode(_MODULE_INSTALL_TYPEHASH, mods[i].moduleType, mods[i].module, keccak256(mods[i].initData))
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

}
