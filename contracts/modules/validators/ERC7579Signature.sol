// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC7579Signature
/// @notice ERC-7913 signature validator for ONCHAINID accounts. Owns its own per-account
///         signer registry — the account layer (see `SmartAccount._validateUserOp`)
///         authorizes the *validator address* (via `hashAddress(validator)`); this
///         contract authorizes the *signer* it accepts on behalf of that account (via
///         the ERC-7913 blob written at `onInstall` / `setSigner`). One signer per
///         (validator, account) install.
/// @dev Wire format for signatures stays `abi.encode(bytes signer, bytes signature)` —
///      the signer follows ERC-7913: 20 bytes = EOA / 1271, longer = `verifier(20) ||
///      key(rest)`. Wire format is a validator-local convention; the account has no
///      opinion on it and can also host stock OZ validators alongside this one.
///      Signer-management ABI (`onInstall` / `onUninstall` / `setSigner`) follows the
///      OZ `ERC7579ECDSA` shape but keeps the ERC-7913 richness so the installed
///      principal can be an EOA, a 1271 wallet, or a passkey/WebAuthn verifier+key.
contract ERC7579Signature is ERC7579Validator {

    /// @dev Signer registry keyed by installing account. ERC-7201 namespaced storage
    ///      so a singleton deployment is safe against inheritance/upgrade shuffles.
    /// @custom:storage-location erc7201:onchainid.validators.erc7579-signature
    struct SignerStorage {
        mapping(address account => bytes signer) signers;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("onchainid.validators.erc7579-signature")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _SIGNER_STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256(bytes("onchainid.validators.erc7579-signature"))) - 1)
    ) & ~bytes32(uint256(0xff));

    /// @dev `data` is shorter than 20 bytes (an ERC-7913 signer must at least contain
    ///      a 20-byte address / verifier).
    error InvalidSignerLength();

    /// @dev `onInstall` was called for an account that already has a signer set.
    ///      Rotate via {setSigner} or uninstall first.
    error AlreadyInstalled();

    /// @dev Emitted whenever an account's signer is set, rotated, or cleared. The
    ///      signer blob is empty on clear.
    event SignerSet(address indexed account, bytes signer);

    /// @notice Returns the ERC-7913 signer blob currently authorized for `account`,
    ///         or zero-length bytes if none configured.
    function signer(address account) external view returns (bytes memory) {
        return _s().signers[account];
    }

    /// @dev Called by the account when it installs this validator. `data` is the
    ///      ERC-7913 signer blob the account authorizes at install time (≥20 bytes).
    ///      Reverts if a signer is already set — rotate via {setSigner}.
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 20, InvalidSignerLength());
        SignerStorage storage s = _s();
        require(s.signers[msg.sender].length == 0, AlreadyInstalled());
        s.signers[msg.sender] = data;
        emit SignerSet(msg.sender, data);
    }

    /// @dev Clears the installing account's signer entry. Idempotent — safe to call
    ///      even if no signer is registered.
    function onUninstall(
        bytes calldata /* data */
    )
        public
        virtual
        override
    {
        SignerStorage storage s = _s();
        if (s.signers[msg.sender].length != 0) {
            delete s.signers[msg.sender];
            emit SignerSet(msg.sender, "");
        }
    }

    /// @notice Rotate the signer for the caller account. Only the account itself may
    ///         invoke this (self-call from `execute`, MANAGEMENT-gated by the per-target
    ///         rule). Pass an empty blob to disable without uninstalling.
    function setSigner(bytes calldata newSigner) external {
        SignerStorage storage s = _s();
        if (newSigner.length == 0) {
            if (s.signers[msg.sender].length != 0) {
                delete s.signers[msg.sender];
                emit SignerSet(msg.sender, "");
            }
            return;
        }
        require(newSigner.length >= 20, InvalidSignerLength());
        s.signers[msg.sender] = newSigner;
        emit SignerSet(msg.sender, newSigner);
    }

    /// @dev Two-step check:
    ///        1. Membership: the decoded signer must equal the ERC-7913 blob the
    ///           account authorized at install / rotation time.
    ///        2. Crypto: the signature must verify against `hash` under ERC-7913
    ///           dispatch (ECDSA / 1271 / verifier+key).
    ///      Both must hold — otherwise `false` propagates to the account-layer
    ///      dispatchers as `SIG_VALIDATION_FAILED` (4337) or `0xffffffff` (1271).
    function _rawERC7579Validation(address account, bytes32 hash, bytes calldata moduleSignature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        /// Crypto dispatch avoids `SignatureChecker.isValidSignatureNow(bytes,...)` because
        /// its `signer.code.length` check violates ERC-7562 bundler validation rules
        // Decode the wire payload. Reverts on malformed input; caller catches it.
        (bytes memory signerBytes, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        if (signerBytes.length < 20) return false;

        // Registry check — compare via keccak so we skip an equal-length bytes loop.
        bytes memory authorized = _s().signers[account];
        if (authorized.length == 0 || keccak256(signerBytes) != keccak256(authorized)) return false;

        if (signerBytes.length == 20) {
            address signerAddr = address(bytes20(signerBytes));
            if (SignatureChecker.isValidERC1271SignatureNow(signerAddr, hash, signature)) return true;
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
            return err == ECDSA.RecoverError.NoError && recovered == signerAddr;
        }

        address verifier = address(bytes20(signerBytes));
        bytes memory key = Bytes.slice(signerBytes, 20);
        (bool success, bytes memory result) =
            verifier.staticcall(abi.encodeCall(IERC7913SignatureVerifier.verify, (key, hash, signature)));
        return success && result.length >= 32
            && abi.decode(result, (bytes32)) == bytes32(IERC7913SignatureVerifier.verify.selector);
    }

    function _s() private pure returns (SignerStorage storage s) {
        bytes32 slot = _SIGNER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

}
