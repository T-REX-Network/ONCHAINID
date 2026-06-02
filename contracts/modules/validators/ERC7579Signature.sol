// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import { IERC734 } from "../../interface/IERC734.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";
import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC7579Signature
/// @notice Single validator for ONCHAINID accounts. Verifies the signature, then checks
///         the signer has ACTION purpose on the account.
/// @dev Wire format: `abi.encode(bytes signer, bytes signature)`. The `signer` follows
///      ERC-7913: 20 bytes = EOA / 1271, longer = `verifier(20) || key(rest)`.
contract ERC7579Signature is ERC7579Validator {

    /// @dev Used by both the 1271 path (inherited) and the 4337 path (inherited).
    ///      Account adds the per-target rule on top for 4337.
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
        (bytes memory signer, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        if (signer.length < 20) return false;

        bool valid;
        if (signer.length == 20) {
            address signerAddr = address(bytes20(signer));
            valid = SignatureChecker.isValidERC1271SignatureNow(signerAddr, hash, signature);
            if (!valid) {
                (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
                valid = err == ECDSA.RecoverError.NoError && recovered == signerAddr;
            }
        } else {
            address verifier = address(bytes20(signer));
            bytes memory key = Bytes.slice(signer, 20);
            (bool success, bytes memory result) =
                verifier.staticcall(abi.encodeCall(IERC7913SignatureVerifier.verify, (key, hash, signature)));
            valid = success && result.length >= 32
                && abi.decode(result, (bytes32)) == bytes32(IERC7913SignatureVerifier.verify.selector);
        }

        // Check the signer is allowed on this account.
        return valid && IERC734(account).keyHasPurpose(keccak256(signer), KeyPurposes.ACTION);
    }

    /// @dev Stateless. No setup.
    function onInstall(bytes calldata) public virtual override { }

    /// @dev Stateless. No cleanup.
    function onUninstall(bytes calldata) public virtual override { }

}
