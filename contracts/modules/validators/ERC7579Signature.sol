// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC7579Signature
/// @notice ERC-7913 signature validator for ONCHAINID accounts. Verifies the signature
///         cryptographically; authorization (ACTION / MANAGEMENT) is enforced at the
///         account layer against the validator address itself under the
///         "validators-as-keys" model.
/// @dev Wire format: `abi.encode(bytes signer, bytes signature)`. The `signer` follows
///      ERC-7913: 20 bytes = EOA / 1271, longer = `verifier(20) || key(rest)`. This is a
///      validator-local convention (needed to route between ECDSA / 1271 / 7913
///      verification); the account has no opinion on it and can also host stock
///      OpenZeppelin validators alongside this one.
contract ERC7579Signature is ERC7579Validator {

    /// @dev Used by both the 1271 path (inherited) and the 4337 path (inherited).
    ///      Purpose enforcement lives on the account: {SmartAccount._validateUserOp}
    ///      applies the per-target rule against `hashAddress(validator)`, so this
    ///      validator does not itself query ERC-734 purposes.
    function _rawERC7579Validation(
        address,
        /* account */
        bytes32 hash,
        bytes calldata moduleSignature
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        /// Crypto dispatch avoids `SignatureChecker.isValidSignatureNow(bytes,...)` because
        /// its `signer.code.length` check violates ERC-7562 bundler validation rules
        // Decode the wire payload. Reverts on malformed input; caller catches it.
        (bytes memory signer, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        if (signer.length < 20) return false;

        if (signer.length == 20) {
            address signerAddr = address(bytes20(signer));
            if (SignatureChecker.isValidERC1271SignatureNow(signerAddr, hash, signature)) return true;
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
            return err == ECDSA.RecoverError.NoError && recovered == signerAddr;
        }

        address verifier = address(bytes20(signer));
        bytes memory key = Bytes.slice(signer, 20);
        (bool success, bytes memory result) =
            verifier.staticcall(abi.encodeCall(IERC7913SignatureVerifier.verify, (key, hash, signature)));
        return success && result.length >= 32
            && abi.decode(result, (bytes32)) == bytes32(IERC7913SignatureVerifier.verify.selector);
    }

    /// @dev Stateless. No setup.
    function onInstall(bytes calldata) public virtual override { }

    /// @dev Stateless. No cleanup.
    function onUninstall(bytes calldata) public virtual override { }

}
