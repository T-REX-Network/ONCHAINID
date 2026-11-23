// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ERC7739Utils } from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";
import { Identity } from "contracts/Identity.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

import { ERC7739Hashes } from "../helpers/ERC7739Hashes.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice An ERC-1271 signature must be bound to the identity that verifies it. The same
///         key often controls several accounts, so a signature over the app's raw hash would be
///         valid for each of them. Identities follow ERC-7739: the key signs the app's hash
///         nested in a struct on the identity's own EIP-712 domain.
///
///         `signer` holds ACTION on both `aliceIdentity` and `bobIdentity`.
contract ERC1271BindingTest is OnchainIDSetup {

    bytes4 internal constant MAGIC = IERC1271.isValidSignature.selector;
    bytes4 internal constant INVALID = 0xffffffff;

    /// @dev A stand-in app request: its domain separator and a typed `Mail(uint256 id)` message.
    bytes32 internal constant APP_SEPARATOR = keccak256("some app domain");
    bytes32 internal constant MAIL_TYPEHASH = keccak256("Mail(uint256 id)");

    address internal signer;
    uint256 internal signerPk;

    function setUp() public override {
        super.setUp();
        (signer, signerPk) = makeAddrAndKey("shared-signer");
        _grantAction(aliceIdentity, alice);
        _grantAction(bobIdentity, bob);
    }

    // ---- what is rejected ------------------------------------------------------------------

    /// @notice The old format: the key signs the app's hash directly. It names no account, so
    ///         it is no longer accepted.
    function test_rawHashSignature_isRejected() public view {
        bytes32 appHash = keccak256("permit");
        assertEq(_isValid(aliceIdentity, appHash, _keySignature(appHash)), INVALID);
    }

    /// @notice The replay from the report: a signature made for alice's identity is not valid
    ///         for bob's, even though the same key acts for both.
    function test_signatureForOneIdentity_isRejectedByAnother() public view {
        bytes32 appHash = keccak256("permit");
        bytes memory forAlice = _keySignature(ERC7739Hashes.personalSign(address(aliceIdentity), appHash));

        assertEq(_isValid(aliceIdentity, appHash, forAlice), MAGIC, "valid for the identity it names");
        assertEq(_isValid(bobIdentity, appHash, forAlice), INVALID, "not valid for another identity");
    }

    /// @notice A typed data envelope must match the hash the app asks about.
    function test_typedData_forAnotherHash_isRejected() public view {
        bytes memory signature = _typedDataSignature(aliceIdentity, 1);
        bytes32 otherAppHash = MessageHashUtils.toTypedDataHash(APP_SEPARATOR, _mailHash(2));
        assertEq(_isValid(aliceIdentity, otherAppHash, signature), INVALID);
    }

    /// @notice A descriptor with no type name ("(uint256 id)") nests the message in nothing: the
    ///         hash left to sign names neither the identity nor the message. Signing it once
    ///         must not give a signature that either identity accepts.
    function test_typedData_withMalformedDescriptor_isRejected() public view {
        bytes32 appHash = MessageHashUtils.toTypedDataHash(APP_SEPARATOR, _mailHash(1));
        bytes32 hashNamingNoAccount = MessageHashUtils.toTypedDataHash(APP_SEPARATOR, bytes32(0));
        bytes memory signature = ERC7739Utils.encodeTypedDataSig(
            _keySignature(hashNamingNoAccount), APP_SEPARATOR, _mailHash(1), "(uint256 id)"
        );

        assertEq(_isValid(aliceIdentity, appHash, signature), INVALID, "rejected by alice's identity");
        assertEq(_isValid(bobIdentity, appHash, signature), INVALID, "rejected by bob's identity");
    }

    // ---- what is accepted ------------------------------------------------------------------

    /// @notice ERC-7739 personal message: `PersonalSign(bytes prefixed)` on the identity's domain.
    function test_personalSign_isAccepted() public view {
        bytes32 appHash = keccak256("hello");
        bytes memory signature = _keySignature(ERC7739Hashes.personalSign(address(aliceIdentity), appHash));
        assertEq(_isValid(aliceIdentity, appHash, signature), MAGIC);
    }

    /// @notice ERC-7739 typed data: the app's struct nested in `TypedDataSign` on the identity's
    ///         domain, then wrapped with the app separator, contents hash and type description.
    function test_typedData_isAccepted() public view {
        bytes32 appHash = MessageHashUtils.toTypedDataHash(APP_SEPARATOR, _mailHash(1));
        assertEq(_isValid(aliceIdentity, appHash, _typedDataSignature(aliceIdentity, 1)), MAGIC);
    }

    // ---- helpers ---------------------------------------------------------------------------

    function _grantAction(Identity identity, address manager) internal {
        vm.prank(manager);
        identity.addKeyWithData(
            keccak256(abi.encodePacked(signer)), KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(signer), ""
        );
    }

    function _mailHash(uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(MAIL_TYPEHASH, id));
    }

    /// @dev The validator's own format, `abi.encode(bytes signer, bytes signature)`, over `hash`.
    function _keySignature(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hash);
        return abi.encode(abi.encodePacked(signer), abi.encodePacked(r, s, v));
    }

    /// @dev An ERC-7739 typed data signature of `Mail(id)` for `identity`.
    function _typedDataSignature(Identity identity, uint256 id) internal view returns (bytes memory) {
        bytes32 nested =
            ERC7739Hashes.typedDataSign(address(identity), APP_SEPARATOR, _mailHash(id), "Mail", "Mail(uint256 id)");
        return ERC7739Utils.encodeTypedDataSig(_keySignature(nested), APP_SEPARATOR, _mailHash(id), "Mail(uint256 id)");
    }

    /// @dev Asks `identity` over ERC-1271, routed to the enshrined validator by its address prefix.
    function _isValid(Identity identity, bytes32 hash, bytes memory signature) internal view returns (bytes4) {
        bytes memory routed = abi.encodePacked(address(onchainidSetup.signatureValidator), signature);
        return IERC1271(address(identity)).isValidSignature(hash, routed);
    }

}
