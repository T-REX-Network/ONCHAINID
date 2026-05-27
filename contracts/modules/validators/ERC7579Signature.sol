// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

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
        // Decode the wire payload. Reverts on malformed input; caller catches it.
        (bytes memory signer, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        if (signer.length < 20) return false;

        // Verify the signature (EOA, 1271, or 7913 verifier, picked by signer length).
        if (!SignatureChecker.isValidSignatureNow(signer, hash, signature)) return false;

        // Check the signer is allowed on this account.
        return IERC734(account).keyHasPurpose(keccak256(signer), KeyPurposes.ACTION);
    }

    /// @dev Stateless. No setup.
    function onInstall(bytes calldata) public virtual override { }

    /// @dev Stateless. No cleanup.
    function onUninstall(bytes calldata) public virtual override { }

}
