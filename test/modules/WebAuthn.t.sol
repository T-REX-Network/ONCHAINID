// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { WebAuthn } from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice WebAuthn / P-256 (ERC-7913) coverage for the unified ERC7579Signature validator.
///         The validator dispatches by `signer.length`: 84-byte payloads go through OZ's
///         SignatureChecker → WebAuthn precompile path, then `keyHasPurpose(ACTION)` on the
///         account. These tests register the P-256 public key as an ACTION key on
///         aliceIdentity and exercise both validateUserOp and isValidSignatureWithSender.
contract WebAuthnSignatureTest is OnchainIDSetup {

    bytes4 internal constant _MAGIC = 0x1626ba7e;
    bytes4 internal constant _INVALID = 0xffffffff;

    ERC7579Signature internal _validator;
    address internal _webauthnVerifier;

    function setUp() public override {
        super.setUp();
        _validator = onchainidSetup.signatureValidator;
        _webauthnVerifier = address(new ERC7913WebAuthnVerifier());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _encodeAuthenticatorData(bytes1 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0), flags, bytes4(0));
    }

    function _encodeClientDataJSON(bytes memory challenge) internal pure returns (string memory) {
        return string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(challenge), '"}');
    }

    /// @dev Builds a P-256 signer of the ERC-7913 form `verifier(20) || qx(32) || qy(32)`,
    ///      signs `challenge`, and returns the validator wire payload `abi.encode(signer, auth)`.
    function _buildSignature(uint256 seed, bytes32 challenge, bytes1 flags)
        internal
        view
        returns (bytes memory signature, bytes memory signer)
    {
        uint256 pk = bound(seed, 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);

        bytes memory authData = _encodeAuthenticatorData(flags);
        string memory clientDataJSON = _encodeClientDataJSON(abi.encodePacked(challenge));

        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, messageHash);
        bytes32 lowS = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r, s: lowS, challengeIndex: 23, typeIndex: 1, authenticatorData: authData, clientDataJSON: clientDataJSON
        });

        // signer = verifier(20) || qx(32) || qy(32) — ERC-7913 form for the WebAuthn verifier.
        signer = abi.encodePacked(_webauthnVerifier, bytes32(x), bytes32(y));
        signature = abi.encode(signer, abi.encode(auth));
    }

    /// @dev Registers `signer` as an ACTION key on aliceIdentity so the validator's
    ///      `keyHasPurpose(ACTION)` check passes.
    function _registerAction(bytes memory signer) internal {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(keccak256(signer), KeyPurposes.ACTION, KeyTypes.WEBAUTHN, signer, "");
    }

    function _userOp(bytes memory signature) internal view returns (PackedUserOperation memory op) {
        op.sender = address(aliceIdentity);
        op.signature = signature;
    }

    // -----------------------------------------------------------------------
    // validateUserOp (4337 path)
    // -----------------------------------------------------------------------

    /// @notice Bad signature → FAILED (no revert).
    function test_webauthn_validateUserOp_failsCleanly() public {
        bytes32 signedChallenge = bytes32(uint256(0x1234));
        bytes32 expectedChallenge = bytes32(uint256(0x9999));
        (bytes memory sig, bytes memory signer) =
            _buildSignature(202, signedChallenge, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);
        _registerAction(signer);

        uint256 result = _validator.validateUserOp(_userOp(sig), expectedChallenge);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /// @notice Valid signature from a P-256 key that is NOT registered on the account → FAILED.
    function test_webauthn_validateUserOp_unregisteredKey_fails() public {
        bytes32 challenge = bytes32(uint256(0xBADD));
        (bytes memory sig,) = _buildSignature(404, challenge, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);
        // Intentionally do NOT register the key.

        uint256 result = _validator.validateUserOp(_userOp(sig), challenge);
        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED, "unregistered P-256 key must fail ACTION gate");
    }

    // -----------------------------------------------------------------------
    // isValidSignatureWithSender (1271 path) — account is `msg.sender`, so we prank.
    // -----------------------------------------------------------------------

    /// @notice Missing UV flag → validator rejects (WebAuthn.verify requireUV).
    function test_webauthn_missingUVFlag_returnsInvalid() public {
        bytes32 challenge = bytes32(uint256(0xABCD));
        (bytes memory sig, bytes memory signer) = _buildSignature(456, challenge, WebAuthn.AUTH_DATA_FLAGS_UP);
        _registerAction(signer);

        vm.prank(address(aliceIdentity));
        assertEq(_validator.isValidSignatureWithSender(address(this), challenge, sig), _INVALID);
    }

    /// @notice Challenge mismatch → invalid.
    function test_webauthn_mismatchedChallenge_returnsInvalid() public {
        bytes32 signedChallenge = bytes32(uint256(0xDEAD));
        bytes32 otherChallenge = bytes32(uint256(0xBEEF));
        (bytes memory sig, bytes memory signer) =
            _buildSignature(789, signedChallenge, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);
        _registerAction(signer);

        vm.prank(address(aliceIdentity));
        assertEq(_validator.isValidSignatureWithSender(address(this), otherChallenge, sig), _INVALID);
    }

    /// @notice Corrupted qy coordinate → public key no longer matches the signature; verify
    ///         returns invalid without reverting.
    function test_webauthn_corruptedSignature_returnsInvalid() public view {
        bytes32 challenge = bytes32(uint256(0xFA11));
        bytes memory sig = _buildSignatureWithCorruptedQy(101, challenge);
        // Note: signer is not registered, but the path we pin here is the signature-verify
        // failure inside SignatureChecker — purpose check is unreachable.
        assertEq(_validator.isValidSignatureWithSender(address(this), challenge, sig), _INVALID);
    }

    function _buildSignatureWithCorruptedQy(uint256 seed, bytes32 challenge) internal view returns (bytes memory) {
        bytes memory authData = _encodeAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);
        string memory clientDataJSON = _encodeClientDataJSON(abi.encodePacked(challenge));
        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(seed, messageHash);
        (uint256 x, uint256 y) = vm.publicKeyP256(seed);
        uint256 corruptedY = y ^ 0xff;

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: bytes32(Math.min(uint256(s), P256.N - uint256(s))),
            challengeIndex: 23,
            typeIndex: 1,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON
        });
        bytes memory signer = abi.encodePacked(_webauthnVerifier, bytes32(x), bytes32(corruptedY));
        return abi.encode(signer, abi.encode(auth));
    }

    /// @notice Signer shorter than 20 bytes is rejected before any signature work.
    function test_webauthn_shortSigner_returnsInvalid() public view {
        bytes memory shortSigner = abi.encodePacked(uint8(0xAA), uint8(0xBB));
        bytes memory inner = abi.encode(uint256(0));
        bytes memory sig = abi.encode(shortSigner, inner);

        assertEq(_validator.isValidSignatureWithSender(address(this), bytes32(0), sig), _INVALID);
    }

    /// @notice Module advertises itself only as MODULE_TYPE_VALIDATOR.
    function test_webauthn_moduleType_isValidatorOnly() public view {
        assertTrue(_validator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(_validator.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_validator.isModuleType(MODULE_TYPE_FALLBACK));
    }

    /// @notice fuzz: random inputs must never leak a `true` result and must not escape
    ///         the consumer's try/catch contract.
    function testFuzz_webauthn_invalidSignatures_dontEscape(bytes32 challenge, bytes calldata sig) public view {
        try this._tryValidate(challenge, sig) returns (bytes4 magic) {
            assertEq(magic, _INVALID);
        } catch {
            // abi.decode reverts on malformed input — caller wraps in try/catch.
        }
    }

    function _tryValidate(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        return _validator.isValidSignatureWithSender(address(this), hash, sig);
    }

}
