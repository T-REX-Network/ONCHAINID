// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { IERC7579Validator, MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice ERC-1271 `isValidSignature` surface coverage on the SmartAccount. Pinned in a
///         dedicated file because the wire format is distinct from `PackedUserOperation`:
///         `prefix(20 bytes validator address) || abi.encode(bytes signer, bytes sig)`.
contract SmartAccountERC1271Test is OnchainIDSetup {

    bytes4 internal constant _MAGIC = 0x1626ba7e;
    bytes4 internal constant _INVALID = 0xffffffff;

    address internal _validator;

    function setUp() public override {
        super.setUp();
        _validator = address(onchainidSetup.signatureValidator);
        // david (ACTION) needs his ECDSA signer to map to a valid registered key already.
    }

    /// @dev Build the SmartAccount.isValidSignature wire format: prefix || abi.encode(signer, sig).
    function _buildSig(address validatorAddr, uint256 pk, address signerAddr, bytes32 hash)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory raw = abi.encodePacked(r, s, v);
        bytes memory signer = abi.encodePacked(signerAddr);
        return abi.encodePacked(validatorAddr, abi.encode(signer, raw));
    }

    /// @notice Valid ACTION signature returns the magic value.
    function test_isValidSignature_actionKey_magic() public view {
        bytes32 hash = keccak256("hello-action");
        bytes memory sig = _buildSig(_validator, davidPk, david, hash);
        assertEq(aliceIdentity.isValidSignature(hash, sig), _MAGIC);
    }

    /// @notice A CLAIM_SIGNER-only signer is rejected — ACTION is the minimum.
    function test_isValidSignature_claimSignerOnly_invalid() public view {
        // carol is CLAIM_SIGNER on alice's identity (no ACTION).
        bytes32 hash = keccak256("carol-claim");
        bytes memory sig = _buildSig(_validator, carolPk, carol, hash);
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

    /// @notice Unknown validator prefix → invalid.
    function test_isValidSignature_unknownValidator_invalid() public view {
        bytes32 hash = keccak256("unknown");
        bytes memory sig = _buildSig(address(0xBEEF), davidPk, david, hash);
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

    /// @notice Signature lengths 0, 1, 19, 20 → invalid (length guard, never reverts).
    function test_isValidSignature_shortSignatures_invalid() public view {
        bytes32 hash = keccak256("len");
        assertEq(aliceIdentity.isValidSignature(hash, ""), _INVALID);
        assertEq(aliceIdentity.isValidSignature(hash, hex"01"), _INVALID);
        assertEq(aliceIdentity.isValidSignature(hash, new bytes(19)), _INVALID);
        // 20 bytes: prefix only, no payload — `isModuleInstalled` returns false for address(0).
        bytes memory twenty = abi.encodePacked(address(0));
        assertEq(aliceIdentity.isValidSignature(hash, twenty), _INVALID);
    }

    /// @notice A malformed inner `abi.encode(signer, sig)` MUST NOT revert — ERC-1271
    ///         requires `isValidSignature` to return `_INVALID` for any malformed input.
    ///         After the validator-collapse refactor the malformed decode is caught inside
    ///         the validator and surfaces as `_INVALID` to the caller.
    function test_isValidSignature_malformedInner_neverReverts() public view {
        bytes32 hash = keccak256("malformed");
        // 20-byte validator prefix + 32 bytes that can't decode as (bytes, bytes).
        bytes memory sig = abi.encodePacked(_validator, bytes32(uint256(1)));
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

    /// @notice Signer not registered as a key on the account → invalid (no revert).
    function test_isValidSignature_unregisteredSigner_invalid() public {
        (address stranger, uint256 strangerPk) = makeAddrAndKey("stranger");
        bytes32 hash = keccak256("unknown-signer");
        bytes memory sig = _buildSig(_validator, strangerPk, stranger, hash);
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

    /// @notice A validator that reverts inside `isValidSignatureWithSender` is caught;
    ///         the outer call returns invalid instead of bubbling.
    function test_isValidSignature_revertingValidator_isCaught() public {
        RevertingValidator rv = new RevertingValidator();
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(rv), "");

        bytes32 hash = keccak256("rv");
        // david is a registered ACTION key; the inner sig payload doesn't matter because the
        // validator always reverts.
        bytes memory inner = abi.encode(abi.encodePacked(david), bytes("ignored"));
        bytes memory sig = abi.encodePacked(address(rv), inner);
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

    /// @notice Fuzz: random hash + short signature must never revert. We restrict the fuzz
    ///         to the sub-20-byte length-guard path so the assertion holds independently of
    ///         the longer-payload behavior covered by `test_isValidSignature_malformedInner_neverReverts`.
    function testFuzz_isValidSignature_neverRevertsWhenLengthGuardCovers(bytes32 hash, uint8 sigSeed) public view {
        // Build a payload shorter than 20 bytes — guaranteed safe path through the length guard.
        uint256 len = sigSeed % 20;
        bytes memory sig = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            sig[i] = bytes1(uint8(i ^ sigSeed));
        }
        assertEq(aliceIdentity.isValidSignature(hash, sig), _INVALID);
    }

}

/// @dev A validator that always reverts during signature checks. Used to verify the outer
///      try/catch around the validator dispatch catches the revert and the account returns
///      `_INVALID` instead of bubbling.
contract RevertingValidator is IERC7579Validator {

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function onInstall(bytes calldata) external pure { }
    function onUninstall(bytes calldata) external pure { }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        revert("nope");
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external pure returns (uint256) {
        revert("nope");
    }

}
