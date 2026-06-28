// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../../helpers/OnchainIDSetup.sol";
import { Identity } from "contracts/Identity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { RecoveryModule } from "contracts/modules/executors/RecoveryModule.sol";

/// @notice Integration tests for {RecoveryModule} against an ONCHAINID identity.
///         Each test pins one part of the recovery surface:
///           * happy path: MANAGEMENT key replaced, recovered key works for every
///             MANAGEMENT-gated op (installModule, addKey, removeKey, queued self-call)
///           * threshold: a quorum below threshold is rejected
///           * signer set: a signature from a non-guardian does not count
///           * cross-identity replay: a signature scoped to alice cannot be used against bob
///           * typehash separation: a SCHEDULE signature cannot be reused as a CANCEL signature
///           * cancel paths: both the account-self-cancel path and the guardian-quorum-cancel path
///           * weighted multisig: a single high-weight guardian can meet a weighted threshold
///
///         setUp() installs the module on alice with 3 guardians, threshold 2,
///         delay 1 day, expiration 30 days, all weights 1.
contract RecoveryModuleTest is OnchainIDSetup {

    RecoveryModule internal recovery;

    address internal g1;
    uint256 internal g1Pk;
    address internal g2;
    uint256 internal g2Pk;
    address internal g3;
    uint256 internal g3Pk;

    address internal newOwner;
    uint256 internal newOwnerPk;

    // Per OZ ERC7579DelayedExecutor.onInstall encoding:
    //   executorArgs = abi.encodePacked(uint32 delay, uint32 expiration)
    uint32 internal constant DELAY = 1 days;
    uint32 internal constant EXPIRATION = 30 days;

    // Per OZ ERC7579MultisigWeighted.onInstall encoding:
    //   multisigArgs = abi.encode(bytes[] signers, uint64 threshold, uint64[] weights)
    uint64 internal constant THRESHOLD = 2;

    function setUp() public override {
        super.setUp();

        recovery = new RecoveryModule();

        (g1, g1Pk) = makeAddrAndKey("guardian1");
        (g2, g2Pk) = makeAddrAndKey("guardian2");
        (g3, g3Pk) = makeAddrAndKey("guardian3");
        (newOwner, newOwnerPk) = makeAddrAndKey("newOwner");

        // OZ's onInstall expects:
        //   [uint16(execLen), execArgs, uint16(msigLen), msigArgs]
        bytes memory execArgs = abi.encodePacked(DELAY, EXPIRATION);

        bytes[] memory guardians = new bytes[](3);
        guardians[0] = abi.encodePacked(g1);
        guardians[1] = abi.encodePacked(g2);
        guardians[2] = abi.encodePacked(g3);
        uint64[] memory weights = new uint64[](3);
        weights[0] = 1;
        weights[1] = 1;
        weights[2] = 1;
        bytes memory msigArgs = abi.encode(guardians, THRESHOLD, weights);

        bytes memory installData =
            abi.encodePacked(uint16(execArgs.length), execArgs, uint16(msigArgs.length), msigArgs);

        // Install as an executor, then register the module address as a MODULE-typed
        // MANAGEMENT key so SmartAccount accepts its self-targeted dispatches.
        // KeyApprovalModule does the same thing for the same reason.
        vm.startPrank(alice);
        aliceIdentity.installModule(
            2,
            /* MODULE_TYPE_EXECUTOR */
            address(recovery),
            installData
        );
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(recovery))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(recovery)),
            ""
        );
        vm.stopPrank();
    }

    /// @notice Happy path. Schedule a recovery that grants newOwner the MANAGEMENT
    ///         purpose, warp past the delay, execute, then run every MANAGEMENT
    ///         gated operation as newOwner: installModule, addKey, removeKey, and
    ///         a self-targeted queued call through KeyApprovalModule. If any of
    ///         those fail, the recovered key isn't actually equivalent to the
    ///         original, which is the whole thing we're trying to prove.
    function test_recoveredKeyHasFullManagementAuthority() public {
        bytes32 salt = bytes32(uint256(1));
        bytes32 mode = bytes32(0); // CALLTYPE_SINGLE + EXECTYPE_DEFAULT

        // Payload: self-targeted addKey installing newOwner as MANAGEMENT.
        bytes memory inner = abi.encodeWithSignature(
            "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
            keccak256(abi.encodePacked(newOwner)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(newOwner),
            ""
        );
        // ERC-7579 single-call shape: target ++ value ++ data.
        bytes memory recoveryData = abi.encodePacked(address(aliceIdentity), uint256(0), inner);

        // Digest is scoped to alice's EIP-712 domain (verifyingContract = aliceIdentity).
        // That's what stops the same signatures from being replayed against any other
        // identity that happens to use this same module singleton.
        bytes32 digest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);

        // Two parallel arrays. signers[i] is the signer for signatures[i].
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        sigs[0] = _sign(g1Pk, digest);
        sigs[1] = _sign(g2Pk, digest);

        bytes memory multisignature = abi.encode(signers, sigs);

        // Anyone can submit the bundle. The authorization lives in the sigs, not in msg.sender.
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, multisignature);

        // Before the delay elapses the op is still Scheduled, so execute reverts.
        vm.expectRevert();
        recovery.executeRecovery(address(aliceIdentity), salt, mode, recoveryData);

        // After the delay, anyone (literally) can trigger the execution.
        vm.warp(block.timestamp + DELAY);
        recovery.executeRecovery(address(aliceIdentity), salt, mode, recoveryData);

        // Sanity check: the new MANAGEMENT key actually landed.
        assertTrue(aliceIdentity.keyHasPurpose(keccak256(abi.encodePacked(newOwner)), KeyPurposes.MANAGEMENT));

        // Everything below this point runs as newOwner. If any of these revert,
        // the "recovered key" isn't actually a full-authority MANAGEMENT key.
        vm.startPrank(newOwner);

        // 1. installModule (gated by onlyManager on SmartAccount).
        RecoveryModule second = new RecoveryModule();
        bytes[] memory g = new bytes[](1);
        g[0] = abi.encodePacked(g1);
        uint64[] memory w = new uint64[](1);
        w[0] = 1;
        bytes memory msig2 = abi.encode(g, uint64(1), w);
        bytes memory exec2 = abi.encodePacked(uint32(2 days), uint32(30 days));
        bytes memory init2 = abi.encodePacked(uint16(exec2.length), exec2, uint16(msig2.length), msig2);
        aliceIdentity.installModule(2, address(second), init2);

        // 2. addKey directly (also onlyManager).
        address actionKey = makeAddr("recoveredActionKey");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(actionKey)), KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(actionKey), ""
        );

        // 3. removeKey on alice's old MANAGEMENT key, the one we're modelling as lost.
        aliceIdentity.removeKey(keccak256(abi.encodePacked(alice)), KeyPurposes.MANAGEMENT);
        assertFalse(aliceIdentity.keyHasPurpose(keccak256(abi.encodePacked(alice)), KeyPurposes.MANAGEMENT));

        vm.stopPrank();

        // 4. Queue a self-targeted call through KeyApprovalModule. The queue's
        //    auto-approval for a self-target requires MANAGEMENT on the caller,
        //    so this is the strictest path that newOwner has to clear.
        vm.prank(newOwner);
        address queuedActionKey = makeAddr("queuedActionKey");
        IKeyExecutor(address(aliceIdentity))
            .execute(
                address(aliceIdentity),
                0,
                abi.encodeWithSignature(
                    "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
                    keccak256(abi.encodePacked(queuedActionKey)),
                    KeyPurposes.ACTION,
                    KeyTypes.ECDSA,
                    abi.encodePacked(queuedActionKey),
                    ""
                )
            );
        assertTrue(aliceIdentity.keyHasPurpose(keccak256(abi.encodePacked(queuedActionKey)), KeyPurposes.ACTION));
    }

    /// @notice One signature shouldn't be enough when threshold is 2. Pins this
    ///         in case anyone ever weakens the threshold check.
    function test_revertWhenBelowThreshold() public {
        bytes32 salt = bytes32(uint256(10));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldata();

        bytes32 digest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](1);
        bytes[] memory sigs = new bytes[](1);
        signers[0] = abi.encodePacked(g1);
        sigs[0] = _sign(g1Pk, digest);

        vm.expectRevert();
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));
    }

    /// @notice A signature from someone who isn't a guardian must not count. Bob
    ///         signs alongside g1; bob is not in alice's guardian set, so the bundle
    ///         is effectively 1-of-2 and should be rejected.
    function test_revertWhenNonGuardianSigns() public {
        bytes32 salt = bytes32(uint256(11));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldata();

        bytes32 digest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(bob); // not a guardian
        sigs[0] = _sign(g1Pk, digest);
        sigs[1] = _sign(bobPk, digest);

        vm.expectRevert();
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));
    }

    /// @notice The whole point of reading the domain from IERC5267(account) is
    ///         that a signature for alice cannot be replayed against bob. This
    ///         test verifies that, by signing for alice and trying to submit the
    ///         same bundle against bob's identity. Bob is configured identically
    ///         so the only relevant difference is the verifyingContract field
    ///         baked into the digest.
    function test_revertOnCrossIdentityReplay() public {
        // Bob gets the same config as alice. That way the only thing that differs
        // between the two startRecovery calls is the target identity itself.
        bytes memory execArgs = abi.encodePacked(DELAY, EXPIRATION);
        bytes[] memory guardians = new bytes[](3);
        guardians[0] = abi.encodePacked(g1);
        guardians[1] = abi.encodePacked(g2);
        guardians[2] = abi.encodePacked(g3);
        uint64[] memory weights = new uint64[](3);
        weights[0] = 1;
        weights[1] = 1;
        weights[2] = 1;
        bytes memory msigArgs = abi.encode(guardians, THRESHOLD, weights);
        bytes memory installData =
            abi.encodePacked(uint16(execArgs.length), execArgs, uint16(msigArgs.length), msigArgs);

        vm.startPrank(bob);
        bobIdentity.installModule(2, address(recovery), installData);
        bobIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(recovery))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(recovery)),
            ""
        );
        vm.stopPrank();

        bytes32 salt = bytes32(uint256(12));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldata();

        // Guardians sign for alice's identity.
        bytes32 aliceDigest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        sigs[0] = _sign(g1Pk, aliceDigest);
        sigs[1] = _sign(g2Pk, aliceDigest);

        // Then we submit the same bundle against bob. It should revert because
        // the digest each guardian signed had aliceIdentity as verifyingContract,
        // and bobIdentity's domain has a different verifyingContract.
        vm.expectRevert();
        recovery.startRecovery(address(bobIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));
    }

    /// @notice Schedule signatures and cancel signatures use different EIP-712
    ///         typehashes, so a schedule bundle should not double as a cancel
    ///         bundle. Otherwise guardians who agreed to schedule a recovery
    ///         would implicitly authorize cancelling it too.
    function test_revertWhenScheduleSigReplayedAsCancel() public {
        bytes32 salt = bytes32(uint256(13));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldata();

        // First, schedule with a real quorum so there's something to attempt cancelling.
        bytes32 scheduleDigest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        sigs[0] = _sign(g1Pk, scheduleDigest);
        sigs[1] = _sign(g2Pk, scheduleDigest);
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));

        // Now try to cancel by handing in the schedule signatures. The default
        // caller is the test contract, not the identity, so OZ takes the multisig
        // branch. That branch validates against CANCEL_RECOVER_TYPEHASH, so the
        // schedule digest won't match.
        vm.expectRevert();
        recovery.cancelRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));
    }

    /// @notice There are two cancel paths. The account-self path is covered in
    ///         test_accountSelfCancelStopsRecovery; this one covers the guardian
    ///         quorum path. We sign a fresh CANCEL bundle (different guardians
    ///         than the schedulers, for good measure) and submit from an
    ///         unrelated caller.
    function test_guardianQuorumCanCancel() public {
        bytes32 salt = bytes32(uint256(14));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldata();

        // Same setup as above: schedule first so there's something to cancel.
        bytes32 scheduleDigest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        sigs[0] = _sign(g1Pk, scheduleDigest);
        sigs[1] = _sign(g2Pk, scheduleDigest);
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));

        // Sign a fresh bundle over the CANCEL typehash. The caller (bob) doesn't
        // matter to OZ, only the signatures do.
        bytes32 cancelDigest = _cancelDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory cSigners = new bytes[](2);
        bytes[] memory cSigs = new bytes[](2);
        cSigners[0] = abi.encodePacked(g1);
        cSigners[1] = abi.encodePacked(g3); // different guardian than the scheduler
        cSigs[0] = _sign(g1Pk, cancelDigest);
        cSigs[1] = _sign(g3Pk, cancelDigest);

        vm.prank(bob);
        recovery.cancelRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(cSigners, cSigs));

        // Execute after the delay should now fail, because the op is Canceled.
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert();
        recovery.executeRecovery(address(aliceIdentity), salt, mode, recoveryData);
    }

    /// @notice Sanity check on the weighted multisig: with weights {g1:3, g2:1,
    ///         g3:1} and threshold 3, g1 alone should be enough. If this fails,
    ///         the multisig is counting signatures instead of summing weights.
    function test_weightedThresholdReachedBySingleHeavyGuardian() public {
        // We install a fresh module on bob's identity with the weighted config.
        // Using a separate module + identity avoids stepping on the default
        // setUp() install on alice.
        RecoveryModule heavyRecovery = new RecoveryModule();

        bytes memory execArgs = abi.encodePacked(DELAY, EXPIRATION);
        bytes[] memory guardians = new bytes[](3);
        guardians[0] = abi.encodePacked(g1);
        guardians[1] = abi.encodePacked(g2);
        guardians[2] = abi.encodePacked(g3);
        uint64[] memory weights = new uint64[](3);
        weights[0] = 3; // g1 has weight 3
        weights[1] = 1;
        weights[2] = 1;
        uint64 weightedThreshold = 3;
        bytes memory msigArgs = abi.encode(guardians, weightedThreshold, weights);
        bytes memory installData =
            abi.encodePacked(uint16(execArgs.length), execArgs, uint16(msigArgs.length), msigArgs);

        // bob has no recovery module installed yet, so we install the weighted one.
        vm.startPrank(bob);
        bobIdentity.installModule(2, address(heavyRecovery), installData);
        bobIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(heavyRecovery))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(heavyRecovery)),
            ""
        );
        vm.stopPrank();

        bytes32 salt = bytes32(uint256(15));
        bytes32 mode = bytes32(0);
        bytes memory recoveryData = _addNewOwnerCalldataFor(address(bobIdentity));

        // One signature, from g1, who has weight 3. Threshold is 3, so this alone passes.
        bytes32 digest = _scheduleDigestFor(heavyRecovery, address(bobIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](1);
        bytes[] memory sigs = new bytes[](1);
        signers[0] = abi.encodePacked(g1);
        sigs[0] = _sign(g1Pk, digest);

        heavyRecovery.startRecovery(address(bobIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));

        vm.warp(block.timestamp + DELAY);
        heavyRecovery.executeRecovery(address(bobIdentity), salt, mode, recoveryData);

        assertTrue(bobIdentity.keyHasPurpose(keccak256(abi.encodePacked(newOwner)), KeyPurposes.MANAGEMENT));
    }

    /// @notice The account can cancel a pending recovery on its own, without a
    ///         quorum. We schedule one, cancel as the identity, warp past the
    ///         delay, and confirm execute now rejects (op is Canceled).
    function test_accountSelfCancelStopsRecovery() public {
        bytes32 salt = bytes32(uint256(2));
        bytes32 mode = bytes32(0);
        bytes memory inner = abi.encodeWithSignature(
            "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
            keccak256(abi.encodePacked(newOwner)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(newOwner),
            ""
        );
        bytes memory recoveryData = abi.encodePacked(address(aliceIdentity), uint256(0), inner);

        bytes32 digest = _scheduleDigest(address(aliceIdentity), salt, mode, recoveryData);
        bytes[] memory signers = new bytes[](2);
        bytes[] memory sigs = new bytes[](2);
        signers[0] = abi.encodePacked(g1);
        signers[1] = abi.encodePacked(g2);
        sigs[0] = _sign(g1Pk, digest);
        sigs[1] = _sign(g2Pk, digest);
        recovery.startRecovery(address(aliceIdentity), salt, mode, recoveryData, abi.encode(signers, sigs));

        // Account self-cancels.
        vm.prank(address(aliceIdentity));
        recovery.cancelRecovery(address(aliceIdentity), salt, mode, recoveryData);

        // Execute now reverts because the operation is in Canceled state.
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert();
        recovery.executeRecovery(address(aliceIdentity), salt, mode, recoveryData);
    }

    // ---- helpers ----

    /// @dev Builds the SCHEDULE digest a guardian needs to sign. The domain we use
    ///      here is the identity's, not the module's, because OZ's _getTypedHash
    ///      reads it via IERC5267(account).eip712Domain().
    function _scheduleDigest(address account, bytes32 salt, bytes32 mode, bytes memory recoveryData)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(recovery.SCHEDULE_RECOVER_TYPEHASH(), salt, mode, keccak256(recoveryData)));
        return _domainHash(account, structHash);
    }

    function _domainHash(address account, bytes32 structHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            Identity(payable(account)).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Same idea as _scheduleDigest, but for the CANCEL typehash.
    function _cancelDigest(address account, bytes32 salt, bytes32 mode, bytes memory recoveryData)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(recovery.CANCEL_RECOVER_TYPEHASH(), salt, mode, keccak256(recoveryData)));
        return _domainHash(account, structHash);
    }

    /// @dev The recovery payload most tests reuse: a self-targeted addKey that
    ///      installs newOwner as MANAGEMENT on alice's identity.
    function _addNewOwnerCalldata() internal view returns (bytes memory) {
        return _addNewOwnerCalldataFor(address(aliceIdentity));
    }

    /// @dev Same payload, but for whichever account you pass in.
    function _addNewOwnerCalldataFor(address account) internal view returns (bytes memory) {
        bytes memory inner = abi.encodeWithSignature(
            "addKeyWithData(bytes32,uint256,uint256,bytes,bytes)",
            keccak256(abi.encodePacked(newOwner)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(newOwner),
            ""
        );
        return abi.encodePacked(account, uint256(0), inner);
    }

    /// @dev Like _scheduleDigest, but lets you point at a specific module instance.
    ///      Needed by the weighted-threshold test, which uses a second module.
    function _scheduleDigestFor(
        RecoveryModule mod,
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes memory recoveryData
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(mod.SCHEDULE_RECOVER_TYPEHASH(), salt, mode, keccak256(recoveryData)));
        return _domainHash(account, structHash);
    }

}
