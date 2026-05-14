// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    Execution,
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Calldata } from "@openzeppelin/contracts/utils/Calldata.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import { KeyManager } from "./KeyManager.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";

/**
 * @title SmartAccount
 * @notice ERC-7579 modular account layer for ONCHAINID. Bridges the ERC-734 key registry
 *         ({KeyManager}) with the ERC-4337 / ERC-7579 validation pipeline.
 *
 *         Execution flows through exactly one entry point: the inherited
 *         `AccountERC7579Upgradeable.execute(bytes32 mode, bytes executionCalldata)`. The
 *         legacy ERC-734 `execute(address,uint256,bytes)` and `approve(uint256,bool)` ABI
 *         live on the installed {KeyApprovalModule} via ERC-7579 fallback handler.
 */
abstract contract SmartAccount is KeyManager, AccountERC7579Upgradeable, EIP712 {

    /// @dev ERC-1271 failure sentinel.
    bytes4 internal constant _SIG_INVALID = 0xffffffff;

    receive() external payable virtual override { }

    /**
     * @notice Install an ERC-7579 module.
     * @dev Overrides OZ's `onlyEntryPointOrSelf` with `onlyManager`. A MANAGEMENT key is the
     *      same authority OZ relies on through the EntryPoint — this just removes the detour
     *      so the factory can install modules at bootstrap, before any UserOp exists.
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        virtual
        override
        delegatedOnly
        onlyManager
    {
        _installModule(moduleTypeId, module, initData);
    }

    /**
     * @notice ERC-1271 signature validation. Answers "did this account authorize this message?"
     *         on behalf of off-chain consumers (dApps, marketplaces, DeFi protocols).
     *
     * @param hashToVerify The 32-byte digest the user claims to have signed. The off-chain
     *        flow is application-specific — most commonly the EIP-712 hash of a typed-data
     *        struct (e.g. a Permit, a Seaport order). The account does not interpret it; it
     *        only verifies that the signature is a valid signature of this hash by an
     *        authorized signer.
     * @param signature Layout: `address module (20 bytes) || moduleSignature (variable)`.
     *        - `module` is the address of an installed ERC-7579 validator module.
     *        - `moduleSignature` is module-defined; current shape is
     *          `abi.encode(bytes signer, bytes sig)`.
     *
     * @return The ERC-1271 magic value `IERC1271.isValidSignature.selector` (`0x1626ba7e`)
     *         when valid; `0xffffffff` ({_SIG_INVALID}) on any failure. MUST never revert.
     *
     * @dev Authorization gate: the signer key must have ACTION purpose on this identity.
     *      MANAGEMENT keys also satisfy via the universal-purpose rule in
     *      {KeyManager.keyHasPurpose}. CLAIM_SIGNER / CLAIM_ADDER cannot sign arbitrary
     *      off-chain messages on behalf of the account — they are scoped to claims.
     */
    function isValidSignature(bytes32 hashToVerify, bytes calldata signature)
        public
        view
        virtual
        override
        returns (bytes4)
    {
        if (signature.length < 20) return _SIG_INVALID;

        (address module, bytes calldata moduleSignature) = _extractSignatureValidator(signature);
        if (!isModuleInstalled(MODULE_TYPE_VALIDATOR, module, Calldata.emptyBytes())) {
            return _SIG_INVALID;
        }

        // Decode the signer via a self-staticcall so a malformed `moduleSignature` yields the
        // ERC-1271 failure sentinel instead of bubbling a revert.
        try this._extractKeyHash(moduleSignature) returns (bytes32 signerKeyHash) {
            if (!keyHasPurpose(signerKeyHash, KeyPurposes.ACTION)) {
                return _SIG_INVALID;
            }
        } catch {
            return _SIG_INVALID;
        }
        try IERC7579Validator(module).isValidSignatureWithSender(msg.sender, hashToVerify, moduleSignature) returns (
            bytes4 magicValue
        ) {
            return magicValue;
        } catch {
            return _SIG_INVALID;
        }
    }

    /// @dev External-only because it's invoked via `this.` from {isValidSignature} to wrap
    ///      `abi.decode` in a try/catch. Solidity does not allow try/catch on internal calls.
    function _extractKeyHash(bytes calldata moduleSignature) external pure returns (bytes32) {
        (bytes memory signerBytes,) = abi.decode(moduleSignature, (bytes, bytes));
        return keccak256(signerBytes);
    }

    /**
     * @notice ERC-4337 UserOperation validation. Called by the EntryPoint *before* the
     *         operation's execution phase. Returns success or failure as packed validation
     *         data; the EntryPoint never proceeds to `execute` if this returns failure.
     *
     * @param userOp The full UserOperation the bundler submitted. The fields we read are:
     *        - `userOp.nonce` (upper 20 bytes are the validator module address, per ERC-7579).
     *        - `userOp.callData` (the bytes the EntryPoint will call on us after validation).
     *        - `userOp.signature` (the signing material, distinct from `signature` here only
     *          when `_signableUserOpHash` performs ERC-7739-style nesting; in our case they
     *          match).
     * @param userOpHash The canonical 4337 hash the bundler computed over the UserOp. We feed
     *        the *signable* derivative of it (via `_signableUserOpHash`) to the validator
     *        module so signers don't have to be 4337-aware.
     * @param signature The signature blob the user produced off-chain. Shape:
     *        `abi.encode(bytes signer, bytes sig)`.
     *
     * @return validationData Packed ERC-4337 validation result. `SIG_VALIDATION_FAILED` (= 1)
     *         on any failure; the module's own return value (typically `0` for success) on
     *         pass-through. MUST NOT revert — reverts here trigger UserOp rejection at the
     *         bundler level which is a different (worse) failure mode.
     *
     * @dev Three gates, in order:
     *      1. **Module installed.** The validator-module address embedded in `userOp.nonce`
     *         must currently be registered on this account. Prevents callers from naming
     *         arbitrary external modules.
     *      2. **Signer registered.** The keyHash derived from the signature must exist in
     *         this account's ERC-734 registry.
     *      3. **Signer authorized for the call.** The keyHash must have the right ERC-734
     *         purpose for *every* target the UserOp's `callData` ultimately reaches. Without
     *         this check a low-privilege key (e.g. CLAIM_ADDER) could authorize an external
     *         ETH transfer through the inherited `AccountERC7579.execute` path.
     *
     *      Only after all three pass do we delegate the actual cryptographic verification to
     *      the validator module. The module owns "is this signature mathematically valid";
     *      the account owns "is this signer allowed to do this specific thing".
     */
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        virtual
        override
        returns (uint256)
    {
        address module = _extractUserOpValidator(userOp);
        if (!isModuleInstalled(MODULE_TYPE_VALIDATOR, module, Calldata.emptyBytes())) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        (bytes memory signerBytes,) = abi.decode(signature, (bytes, bytes));
        bytes32 signerKeyHash = keccak256(signerBytes);

        if (_getKeyStorage().keys[signerKeyHash].key == bytes32(0)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        if (!canRunUserOp(userOp.callData, signerKeyHash)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        return IERC7579Validator(module).validateUserOp(userOp, _signableUserOpHash(userOp, userOpHash));
    }

    /**
     * @notice Inspects the bytes the EntryPoint will hand to `account.call(...)` and decides
     *         whether the signer has the ERC-734 purpose required for every target it reaches.
     *
     * @param callData The UserOp's callData. MUST be a call to
     *        `AccountERC7579.execute(bytes32 mode, bytes executionCalldata)` on this account
     *        — the single authorized entry point. Any other selector is rejected.
     * @param signerKeyHash The keyHash recovered from the UserOp's signature, already
     *        confirmed to be registered on this account by the caller.
     *
     * @return true iff the signer is authorized for every target the callData implies.
     *
     * @dev Supported execution modes:
     *      - `CALLTYPE_SINGLE`: one (target, value, data). Check the single target.
     *      - `CALLTYPE_BATCH`: an array of `Execution`. Check each element's target.
     *      - `CALLTYPE_DELEGATECALL`: rejected at the validation layer — delegatecall makes
     *        "is this self-targeted" semantically ambiguous (the called code runs in our
     *        storage context), so we refuse to gate it by purpose. If a deployment ever needs
     *        delegatecall it should add an explicit policy module.
     *
     *      The purpose rule per target is encoded in {canCall}: self ⇒ MANAGEMENT, external
     *      ⇒ ACTION. MANAGEMENT satisfies any check via the universal-purpose rule in
     *      {KeyManager.keyHasPurpose}.
     */
    function canRunUserOp(bytes calldata callData, bytes32 signerKeyHash) internal view virtual returns (bool) {
        if (callData.length < 4 || bytes4(callData[:4]) != AccountERC7579Upgradeable.execute.selector) {
            return false;
        }

        (bytes32 modeWord, bytes memory executionCalldata) = abi.decode(callData[4:], (bytes32, bytes));
        (CallType callType,,,) = ERC7579Utils.decodeMode(Mode.wrap(modeWord));

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // SINGLE layout: target(20) || value(32) || data(var). Only the target matters here.
            if (executionCalldata.length < 20) return false;
            address target = address(bytes20(executionCalldata));
            return isKeyAuthorizedToCallTarget(signerKeyHash, target);
        }

        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            Execution[] memory batch = abi.decode(executionCalldata, (Execution[]));
            for (uint256 i = 0; i < batch.length; i++) {
                if (!isKeyAuthorizedToCallTarget(signerKeyHash, batch[i].target)) return false;
            }
            return true;
        }

        return false;
    }

    /// @dev Self-target ⇒ MANAGEMENT required; external target ⇒ ACTION required.
    function isKeyAuthorizedToCallTarget(bytes32 signerKeyHash, address targetAddress) internal view returns (bool) {
        uint256 requiredPurpose = targetAddress == address(this) ? KeyPurposes.MANAGEMENT : KeyPurposes.ACTION;
        return keyHasPurpose(signerKeyHash, requiredPurpose);
    }

}
