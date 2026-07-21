// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IAccount, PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { Execution, MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice Coverage for `ERC734Validator`. Exercises the dual registry (authorization purposes
///         in the validator, identity purposes on the account), per-target scoping, the
///         self-target escalation guard, BATCH scoping, and registry durability across reinstall.
contract ERC734ValidatorTest is OnchainIDSetup {

    address internal constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    ERC734Validator internal validator;

    // Signer registered in the module as the account's MANAGEMENT key at install.
    address internal mgr;
    uint256 internal mgrPk;

    function setUp() public virtual override {
        super.setUp();
        (mgr, mgrPk) = makeAddrAndKey("erc734-mgr");
        validator = new ERC734Validator(address(onchainidSetup.idFactory), address(onchainidSetup.reputationRegistry));

        // Install on alice with `mgr` seeded as the module's MANAGEMENT key.
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(mgr));
    }

    // --- helpers ---------------------------------------------------------

    function _packNonce(address validatorAddr, uint96 seq) internal pure returns (uint256) {
        return (uint256(uint160(validatorAddr)) << 96) | uint256(seq);
    }

    function _buildUserOp(bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory userOp, bytes32 userOpHash)
    {
        userOp = PackedUserOperation({
            sender: address(aliceIdentity),
            nonce: _packNonce(address(validator), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
        userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));
    }

    function _singleExecute(address target, bytes memory innerCall) internal pure returns (bytes memory) {
        bytes memory executionCalldata = abi.encodePacked(target, uint256(0), innerCall);
        return abi.encodeWithSelector(bytes4(keccak256("execute(bytes32,bytes)")), bytes32(0), executionCalldata);
    }

    function _userOpTo(address target, bytes memory innerCall)
        internal
        view
        returns (PackedUserOperation memory userOp, bytes32 userOpHash)
    {
        return _buildUserOp(_singleExecute(target, innerCall));
    }

    function _sign(uint256 signerPk, address who, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hash);
        return abi.encode(abi.encodePacked(who), abi.encodePacked(r, s, v));
    }

    /// @dev Register `who` in the validator with an authorization purpose (via account self-call).
    function _validatorAddKey(address who, uint256 purpose) internal {
        vm.prank(address(aliceIdentity));
        validator.addKey(abi.encodePacked(who), "", purpose, KeyTypes.ECDSA);
    }

    /// @dev Register `who` with a claim purpose in the same validator that validates the userOp.
    ///      Keys and claim purposes now live in one registry per module, so the claim-scoping read
    ///      in `_targetAllowed` resolves against this validator's own registry.
    function _accountAddKey(address who, uint256 purpose) internal {
        vm.prank(address(aliceIdentity));
        validator.addKey(abi.encodePacked(who), "", purpose, KeyTypes.ECDSA);
    }

    function _validate(PackedUserOperation memory userOp, bytes32 userOpHash) internal returns (uint256) {
        vm.prank(ENTRY_POINT);
        return IAccount(address(aliceIdentity)).validateUserOp(userOp, userOpHash, 0);
    }

    // --- purposes -------------------------------------------------------

    /// @notice The module holds every ERC-734 purpose, so CLAIM_SIGNER is accepted and an
    ///         out-of-range purpose reverts.
    function test_moduleAcceptsAllPurposes_rejectsOutOfRange() public {
        vm.startPrank(address(aliceIdentity));

        address who = makeAddr("x");
        validator.addKey(abi.encodePacked(who), "", KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), keccak256(abi.encodePacked(who)), KeyPurposes.CLAIM_SIGNER),
            "CLAIM_SIGNER accepted"
        );

        vm.expectRevert(abi.encodeWithSelector(ERC734Validator.InvalidPurpose.selector, uint256(7)));
        validator.addKey(abi.encodePacked(makeAddr("y")), "", 7, KeyTypes.ECDSA);
        vm.stopPrank();
    }

    /// @notice ERC-1271: only a key that can act for the account (ACTION, or MANAGEMENT) may sign
    ///         as the account. A CLAIM_SIGNER / ENCRYPTION / PROPOSER key is registered but cannot.
    function test_isValidSignature_onlyActionOrManagementKeysAccepted() public {
        bytes32 digest = keccak256("some order to sign");

        // A CLAIM_SIGNER key is registered but must be rejected over ERC-1271.
        (address claimer, uint256 claimerPk) = makeAddrAndKey("claimer-1271");
        _validatorAddKey(claimer, KeyPurposes.CLAIM_SIGNER);
        assertEq(
            IERC1271(address(aliceIdentity)).isValidSignature(digest, _sign1271(claimerPk, claimer, digest)),
            bytes4(0xffffffff),
            "CLAIM_SIGNER must not sign as the account"
        );

        // An ACTION key is accepted.
        (address actor, uint256 actorPk) = makeAddrAndKey("actor-1271");
        _validatorAddKey(actor, KeyPurposes.ACTION);
        assertEq(
            IERC1271(address(aliceIdentity)).isValidSignature(digest, _sign1271(actorPk, actor, digest)),
            IERC1271.isValidSignature.selector,
            "ACTION key signs as the account"
        );
    }

    /// @dev Account 1271 signature: module address prefix, then the validator's `(signer, sig)` blob.
    function _sign1271(uint256 pk, address who, bytes32 digest) internal view returns (bytes memory) {
        return abi.encodePacked(address(validator), _sign(pk, who, digest));
    }

    /// @notice A malformed 1271 signature returns the failure magic through the account. The
    ///         account's own isValidSignature wraps the validator call in try/catch, so a signature
    ///         that can't be decoded is reported as invalid rather than surfacing as a revert.
    function test_isValidSignature_malformed_returnsFailureNotRevert() public view {
        bytes32 digest = keccak256("z");
        bytes memory garbage = abi.encodePacked(address(validator), hex"deadbeef");
        assertEq(
            IERC1271(address(aliceIdentity)).isValidSignature(digest, garbage),
            bytes4(0xffffffff),
            "malformed sig via account must return failure magic"
        );
    }

    /// @notice A registered ERC-7913 signer whose verifier has no code fails validation instead
    ///         of reverting. The verifier is reached via raw staticcall: a codeless verifier
    ///         returns no data and fails the length check, while a high-level call would revert
    ///         the whole `validateUserOp` (Solidity's no-code handling happens in the caller's
    ///         frame, outside any try/catch).
    function test_validateUserOp_codelessVerifier_failsInsteadOfReverting() public {
        // Register a verifier-form signer (20-byte verifier address + key bytes) whose
        // verifier is a plain EOA.
        address eoaVerifier = makeAddr("codeless-verifier");
        bytes memory signerData = abi.encodePacked(eoaVerifier, "some-key");
        vm.prank(address(aliceIdentity));
        validator.addKey(signerData, "", KeyPurposes.ACTION, KeyTypes.ECDSA);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(0xBEEF), "");
        userOp.signature = abi.encode(signerData, bytes("irrelevant"));

        assertEq(
            _validate(userOp, userOpHash),
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "codeless verifier must fail validation, not revert"
        );
    }

    /// @notice A signer shorter than 20 bytes is rejected. The guard lives in `_addKey`, so it
    ///         applies to every caller (here via the public `addKey`).
    function test_addKey_shortSigner_reverts() public {
        // 19 bytes: one short of the 20-byte ERC-7913 minimum.
        bytes memory tooShort = new bytes(19);
        vm.prank(address(aliceIdentity));
        vm.expectRevert(ERC734Validator.InvalidSignerLength.selector);
        validator.addKey(tooShort, "", KeyPurposes.ACTION, KeyTypes.ECDSA);
    }

    /// @notice Removing a purpose the key does not hold reverts instead of silently succeeding.
    function test_removeKey_purposeNotHeld_reverts() public {
        (address who,) = makeAddrAndKey("action-only-key");
        bytes32 keyHash = keccak256(abi.encodePacked(who));
        _validatorAddKey(who, KeyPurposes.ACTION);

        // The key only has ACTION; removing PROPOSER must revert.
        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.KeyDoesNotHavePurpose.selector, keyHash, KeyPurposes.PROPOSER));
        validator.removeKey(keyHash, KeyPurposes.PROPOSER);
    }

    /// @notice A signer that holds both ACTION and CLAIM_SIGNER in the validator's registry:
    ///         external transfer passes (ACTION), but any self-targeted call fails validation.
    ///         Claims are not addable through a user op (the account calls itself, so addClaim sees
    ///         the account as the caller and the account holds no claim key), so self-addClaim is
    ///         rejected at validation to match that execution behaviour; self-addKey needs MANAGEMENT.
    function test_multiPurpose_actionInValidator_claimOnAccount() public {
        (address who, uint256 whoPk) = makeAddrAndKey("multi");
        _validatorAddKey(who, KeyPurposes.ACTION); // authorization purpose -> validator
        _accountAddKey(who, KeyPurposes.CLAIM_SIGNER); // claim purpose -> same validator registry

        // external -> ACTION
        {
            PocCounter counter = new PocCounter();
            (PackedUserOperation memory userOp, bytes32 userOpHash) =
                _userOpTo(address(counter), abi.encodeCall(PocCounter.increment, ()));
            userOp.signature = _sign(whoPk, who, userOpHash);
            assertEq(_validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_SUCCESS, "ACTION external must pass");
        }

        // self + addClaim -> rejected: claims cannot be added through a user op
        {
            bytes memory addClaim = abi.encodeCall(
                IERC735.addClaim,
                (
                    uint256(1),
                    uint256(1),
                    address(claimIssuer),
                    bytes("s"),
                    Structs.ClaimData({ issuedAt: 0, validUntil: 0, payload: bytes("d") }),
                    "u"
                )
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(aliceIdentity), addClaim);
            userOp.signature = _sign(whoPk, who, userOpHash);
            assertEq(
                _validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED, "self-addClaim via userOp must fail"
            );
        }

        // self + addKey -> needs MANAGEMENT
        {
            bytes memory addKey = abi.encodeWithSignature(
                "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.MANAGEMENT, uint256(1)
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(aliceIdentity), addKey);
            userOp.signature = _sign(whoPk, who, userOpHash);
            assertEq(_validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED, "self-addKey must fail");
        }
    }

    /// @notice Claim scoping reads the account: an ACTION member of the validator who is NOT a
    ///         CLAIM_SIGNER on the account cannot self-addClaim.
    function test_actionMember_withoutAccountClaimSigner_cannotAddClaim() public {
        (address who, uint256 whoPk) = makeAddrAndKey("action-only");
        _validatorAddKey(who, KeyPurposes.ACTION);

        bytes memory addClaim = abi.encodeCall(
            IERC735.addClaim,
            (
                uint256(1),
                uint256(1),
                address(claimIssuer),
                bytes("s"),
                Structs.ClaimData({ issuedAt: 0, validUntil: 0, payload: bytes("d") }),
                "u"
            )
        );
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(aliceIdentity), addClaim);
        userOp.signature = _sign(whoPk, who, userOpHash);
        assertEq(
            _validate(userOp, userOpHash),
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "no account CLAIM_SIGNER -> addClaim fails"
        );
    }

    // --- scoping --------------------------------------------------------

    /// @notice The MANAGEMENT signer from install can self-target addKey.
    function test_managementSelfTargets() public {
        bytes memory addKey =
            abi.encodeWithSignature("addKey(bytes32,uint256,uint256)", keccak256("ok"), KeyPurposes.ACTION, uint256(1));
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(aliceIdentity), addKey);
        userOp.signature = _sign(mgrPk, mgr, userOpHash);
        assertEq(
            _validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_SUCCESS, "MANAGEMENT must self-target addKey"
        );
    }

    /// @notice An unregistered signer with a valid signature fails at the module's membership check.
    function test_unregisteredSignerFails() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger734");
        PocCounter counter = new PocCounter();
        (PackedUserOperation memory userOp, bytes32 userOpHash) =
            _userOpTo(address(counter), abi.encodeCall(PocCounter.increment, ()));
        userOp.signature = _sign(strangerPk, stranger, userOpHash);
        assertEq(_validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED, "unregistered signer must fail");
    }

    // --- §5.1 self-target escalation guard ------------------------------

    /// @notice An ACTION member cannot escalate by calling addKey on the validator itself.
    ///         Without the self-target guard, execute(validator, addKey(...)) reads as an
    ///         external target (ACTION suffices) and would grant the attacker MANAGEMENT.
    function test_actionSigner_cannotEscalate_viaValidatorAddKey() public {
        (address who, uint256 whoPk) = makeAddrAndKey("escalator");
        _validatorAddKey(who, KeyPurposes.ACTION);

        (address attacker,) = makeAddrAndKey("attacker");
        bytes memory addMgmt = abi.encodeCall(
            ERC734Validator.addKey, (abi.encodePacked(attacker), "", KeyPurposes.MANAGEMENT, KeyTypes.ECDSA)
        );

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _userOpTo(address(validator), addMgmt);
        userOp.signature = _sign(whoPk, who, userOpHash);
        assertEq(
            _validate(userOp, userOpHash),
            ERC4337Utils.SIG_VALIDATION_FAILED,
            "ACTION must not self-escalate by writing the validator registry"
        );
    }

    // --- §7.4 BATCH scoping ---------------------------------------------

    /// @notice BATCH: every call must pass. An ACTION member can batch two external calls, but a
    ///         batch that includes a self-target addKey fails (needs MANAGEMENT).
    function test_batch_allExternal_pass_but_selfTarget_fails() public {
        (address who, uint256 whoPk) = makeAddrAndKey("batcher");
        _validatorAddKey(who, KeyPurposes.ACTION);

        PocCounter counter = new PocCounter();

        // two external calls -> ok
        {
            Execution[] memory batch = new Execution[](2);
            batch[0] = Execution(address(counter), 0, abi.encodeCall(PocCounter.increment, ()));
            batch[1] = Execution(address(counter), 0, abi.encodeCall(PocCounter.increment, ()));
            bytes memory callData = abi.encodeWithSelector(
                bytes4(keccak256("execute(bytes32,bytes)")),
                bytes32(uint256(0x01) << 248),
                ERC7579Utils.encodeBatch(batch)
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildUserOp(callData);
            userOp.signature = _sign(whoPk, who, userOpHash);
            assertEq(_validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_SUCCESS, "all-external batch must pass");
        }

        // one external + one self-target addKey -> fail
        {
            Execution[] memory batch = new Execution[](2);
            batch[0] = Execution(address(counter), 0, abi.encodeCall(PocCounter.increment, ()));
            batch[1] = Execution(
                address(aliceIdentity),
                0,
                abi.encodeWithSignature(
                    "addKey(bytes32,uint256,uint256)", keccak256("evil"), KeyPurposes.ACTION, uint256(1)
                )
            );
            bytes memory callData = abi.encodeWithSelector(
                bytes4(keccak256("execute(bytes32,bytes)")),
                bytes32(uint256(0x01) << 248),
                ERC7579Utils.encodeBatch(batch)
            );
            (PackedUserOperation memory userOp, bytes32 userOpHash) = _buildUserOp(callData);
            userOp.signature = _sign(whoPk, who, userOpHash);
            assertEq(
                _validate(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED, "batch with self-target must fail"
            );
        }
    }

    // --- §7.3 registry durability across uninstall/reinstall -------------

    /// @notice The registry is durable: it is enshrined in the account implementation and
    ///         {KeyManager} reads it whether or not the module is installed, so neither
    ///         uninstall (a documented no-op hook) nor reinstall touches existing keys.
    ///         Stale keys are removed individually via `removeKey`.
    function test_registryPersistsAcross_uninstallAndReinstall() public {
        (address who,) = makeAddrAndKey("durable");
        bytes32 keyHash = keccak256(abi.encodePacked(who));
        _validatorAddKey(who, KeyPurposes.ACTION);

        (bytes memory before,) = validator.getKeyData(address(aliceIdentity), keyHash);
        assertGt(before.length, 0, "key present before uninstall");

        // Uninstall leaves the record in place (onUninstall is a documented no-op).
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");
        (bytes memory afterUninstall,) = validator.getKeyData(address(aliceIdentity), keyHash);
        assertGt(afterUninstall.length, 0, "uninstall leaves the record in place");

        // Reinstall resumes the same registry: the seed is added, nothing is wiped.
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(alice));

        (bytes memory afterReinstall,) = validator.getKeyData(address(aliceIdentity), keyHash);
        assertGt(afterReinstall.length, 0, "reinstall keeps the existing key record");
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), keyHash, KeyPurposes.ACTION), "purpose survives reinstall"
        );
        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), keccak256(abi.encodePacked(alice)), KeyPurposes.MANAGEMENT),
            "reinstall seed registered alongside the existing keys"
        );
    }

    /// @notice Reinstalling with the same MANAGEMENT seed must not revert: the seed is
    ///         idempotent, so a signer that already holds MANAGEMENT is left untouched
    ///         instead of tripping KeyAlreadyRegistered.
    function test_reinstall_sameSeed_isIdempotent() public {
        bytes32 mgrKey = keccak256(abi.encodePacked(mgr));
        assertTrue(validator.keyHasPurpose(address(aliceIdentity), mgrKey, KeyPurposes.MANAGEMENT), "mgr seeded");

        vm.startPrank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_VALIDATOR, address(validator), "");
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(validator), abi.encodePacked(mgr));
        vm.stopPrank();

        assertTrue(
            validator.keyHasPurpose(address(aliceIdentity), mgrKey, KeyPurposes.MANAGEMENT),
            "mgr still MANAGEMENT after same-seed reinstall"
        );
        uint256[] memory purposes = validator.getKeyPurposes(address(aliceIdentity), mgrKey);
        assertEq(purposes.length, 1, "no duplicate purpose entries from the reseed");
    }

    // --- data preservation ----------------------------------------------

    /// @notice signerData and clientData round-trip through getKeyData/getKey, scoped per account.
    function test_signerAndClientDataPreservedPerAccount() public {
        bytes memory verifier = abi.encodePacked(makeAddr("p256verifier"));
        bytes memory pubkey = abi.encodePacked(keccak256("qx"), keccak256("qy"));
        bytes memory signerData = bytes.concat(verifier, pubkey);
        bytes memory clientData = abi.encodePacked(keccak256("credentialId"));
        bytes32 keyHash = keccak256(signerData);

        vm.prank(address(aliceIdentity));
        validator.addKey(signerData, clientData, KeyPurposes.ACTION, KeyTypes.WEBAUTHN);

        (bytes memory gotSigner, bytes memory gotClient) = validator.getKeyData(address(aliceIdentity), keyHash);
        assertEq(gotSigner, signerData, "signerData preserved");
        assertEq(gotClient, clientData, "clientData preserved");

        (, uint256 keyType, bytes32 key) = validator.getKey(address(aliceIdentity), keyHash);
        assertEq(keyType, KeyTypes.WEBAUTHN, "keyType WEBAUTHN");
        assertEq(key, keyHash, "getKey echoes committed keyHash");

        (bytes memory bobSigner,) = validator.getKeyData(address(bobIdentity), keyHash);
        assertEq(bobSigner.length, 0, "another account must not see this key");
    }

    // --- §3.4 claim read path pinned ------------------------------------

    /// @notice The account's ERC-734 registry is served by its enshrined module (reached via the
    ///         fallback). carol is a CLAIM_SIGNER there, so ERC-735 sees it. This poc installs a
    ///         SECOND, separate validator; it holds its own registry and never sees carol, pinning
    ///         the per-module registry isolation.
    function test_claimSignerLivesOnAccount_notValidator() public view {
        bytes32 carolKey = keccak256(abi.encodePacked(carol));
        assertTrue(
            IERC734(address(aliceIdentity)).keyHasPurpose(carolKey, KeyPurposes.CLAIM_SIGNER),
            "account's enshrined registry holds CLAIM_SIGNER for ERC-735"
        );
        assertFalse(
            validator.keyHasPurpose(address(aliceIdentity), carolKey, KeyPurposes.CLAIM_SIGNER),
            "the separate poc validator does not hold the account's keys"
        );
    }

    // --- ERC-734 getters (msg.sender scoped) ----------------------------

    /// @notice The account-less ERC-734 getters read the caller's registry, so they return the
    ///         same data as the account-scoped getters when called by the account. This is the
    ///         path used when the module is installed as a fallback handler.
    function test_accountLessGetters_readCallerRegistry() public {
        (address who,) = makeAddrAndKey("getter-key");
        bytes32 keyHash = keccak256(abi.encodePacked(who));
        _validatorAddKey(who, KeyPurposes.ACTION);

        vm.startPrank(address(aliceIdentity));
        assertTrue(validator.keyHasPurpose(keyHash, KeyPurposes.ACTION), "keyHasPurpose(bytes32,uint256)");

        uint256[] memory purposes = validator.getKeyPurposes(keyHash);
        assertEq(purposes.length, 1, "getKeyPurposes(bytes32)");
        assertEq(purposes[0], KeyPurposes.ACTION, "purpose is ACTION");

        bytes32[] memory actionKeys = validator.getKeysByPurpose(KeyPurposes.ACTION);
        assertEq(actionKeys.length, 1, "getKeysByPurpose(uint256)");
        assertEq(actionKeys[0], keyHash, "returns the registered key");

        (,, bytes32 gotKey) = validator.getKey(keyHash);
        assertEq(gotKey, keyHash, "getKey(bytes32)");
        vm.stopPrank();

        // A different caller sees an empty registry, since the getters are msg.sender scoped.
        vm.prank(address(bobIdentity));
        assertFalse(validator.keyHasPurpose(keyHash, KeyPurposes.ACTION), "another account sees nothing");
    }

    /// @notice The paginated `(start, end)` overloads of getKeyPurposes / getKeysByPurpose slice
    ///         the enumerable set in [start, end). The account-scoped and msg.sender-scoped
    ///         overloads return the same shape.
    function test_getKeyPurposes_and_getKeysByPurpose_paginated() public {
        // Give one signer three purposes so getKeyPurposes has something to page.
        (address multi,) = makeAddrAndKey("paginated-multi");
        bytes32 multiHash = keccak256(abi.encodePacked(multi));
        _validatorAddKey(multi, KeyPurposes.ACTION);
        _validatorAddKey(multi, KeyPurposes.CLAIM_SIGNER);
        _validatorAddKey(multi, KeyPurposes.PROPOSER);

        // Give three signers ACTION so getKeysByPurpose has something to page.
        (address a,) = makeAddrAndKey("paginated-a");
        (address b,) = makeAddrAndKey("paginated-b");
        _validatorAddKey(a, KeyPurposes.ACTION);
        _validatorAddKey(b, KeyPurposes.ACTION);

        // Account-scoped overloads: full list matches paged [0, N) and tail matches [1, N).
        uint256[] memory allPurposes = validator.getKeyPurposes(address(aliceIdentity), multiHash);
        assertEq(allPurposes.length, 3, "three purposes registered");
        uint256[] memory firstTwo = validator.getKeyPurposes(address(aliceIdentity), multiHash, 0, 2);
        assertEq(firstTwo.length, 2, "first two purposes");
        assertEq(firstTwo[0], allPurposes[0]);
        assertEq(firstTwo[1], allPurposes[1]);
        uint256[] memory lastTwo = validator.getKeyPurposes(address(aliceIdentity), multiHash, 1, 3);
        assertEq(lastTwo.length, 2, "purposes[1..3)");
        assertEq(lastTwo[0], allPurposes[1]);
        assertEq(lastTwo[1], allPurposes[2]);

        // Same shape for byPurpose: three ACTION keys registered above (multi, a, b).
        bytes32[] memory allActions = validator.getKeysByPurpose(address(aliceIdentity), KeyPurposes.ACTION);
        assertEq(allActions.length, 3, "three ACTION keys");
        bytes32[] memory firstTwoActions = validator.getKeysByPurpose(address(aliceIdentity), KeyPurposes.ACTION, 0, 2);
        assertEq(firstTwoActions.length, 2, "first two ACTION keys");
        assertEq(firstTwoActions[0], allActions[0]);
        assertEq(firstTwoActions[1], allActions[1]);
        bytes32[] memory lastActions = validator.getKeysByPurpose(address(aliceIdentity), KeyPurposes.ACTION, 1, 3);
        assertEq(lastActions.length, 2, "ACTION keys[1..3)");
        assertEq(lastActions[0], allActions[1]);
        assertEq(lastActions[1], allActions[2]);

        // msg.sender-scoped overloads read the calling account's registry, same result when
        // called by the account itself.
        vm.startPrank(address(aliceIdentity));
        uint256[] memory selfPurposes = validator.getKeyPurposes(multiHash, 0, 3);
        assertEq(selfPurposes.length, 3, "self-scoped purposes match");
        bytes32[] memory selfActions = validator.getKeysByPurpose(KeyPurposes.ACTION, 0, 3);
        assertEq(selfActions.length, 3, "self-scoped ACTION keys match");
        vm.stopPrank();
    }

}

/// @notice PoC-local counter target.
contract PocCounter {

    uint256 public count;

    function increment() external {
        count++;
    }

}
