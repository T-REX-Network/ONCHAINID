// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    Execution,
    IERC7579Validator,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Calldata } from "@openzeppelin/contracts/utils/Calldata.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { KeyManager } from "./KeyManager.sol";
import { Errors } from "./libraries/Errors.sol";
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
 *
 *         An installed executor module's authority on this account is governed by whether
 *         the executor's address — hashed as `keccak256(abi.encodePacked(module))` — is
 *         registered in the ERC-734 key registry with an appropriate purpose. Whoever
 *         manages the identity (typically the factory at bootstrap, MANAGEMENT keys
 *         thereafter) grants this purpose with a normal `addKey` call. Every dispatch from
 *         the module through `executeFromExecutor` then runs through the same per-target
 *         purpose rule as a UserOp signer's key. Modules are therefore not a privileged
 *         bypass surface — they are capped at whatever purpose was granted to their address.
 */
abstract contract SmartAccount is KeyManager, AccountERC7579Upgradeable, EIP712 {

    using EnumerableSet for EnumerableSet.UintSet;

    /// @dev ERC-1271 failure sentinel.
    bytes4 internal constant _SIG_INVALID = 0xffffffff;

    receive() external payable virtual override { }

    /**
     * @notice Install an ERC-7579 module. Overrides OZ's `onlyEntryPointOrSelf` with
     *         `onlyManager` so the factory can install at bootstrap, before any UserOp.
     * @dev Standard 7579 calldata shape. To grant the installed module authority on this
     *      account, follow up with a regular `addKey(keccak256(abi.encodePacked(module)),
     *      purpose, KeyTypes.ECDSA)` call. See `executeFromExecutor` for how the registered
     *      purpose gates each dispatch.
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        virtual
        override
        delegatedOnly
        onlyManager
    {
        // `onlyManager` replaces OZ's `onlyEntryPointOrSelf` — lets the factory install at bootstrap.
        _installModule(moduleTypeId, module, initData);
    }

    /// @notice Uninstall an ERC-7579 module. Same gate as {installModule}: only MANAGEMENT
    ///         can call it. A user with MANAGEMENT can swap modules directly, without
    ///         going through the EntryPoint.
    /// @dev Modules are not pinned. Removing a module can only take away rights, never add
    ///      new ones. If you ever need to block removal of a specific module, do it here
    ///      by overriding {_uninstallModule} not inside the module itself, because the
    ///      account, not the module, controls uninstall. Upgrade = uninstall old + install new.
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        virtual
        override
        delegatedOnly
        onlyManager
    {
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    /// @dev Runs the base uninstall first (calls the module's `onUninstall`), then removes
    ///      every ERC-734 purpose held by the module's address. This is the opposite of the
    ///      purpose grant done at install time in `IdFactory._setupIdentity`. Without it, a
    ///      reinstalled module address would keep its old rights. Uninstalling the last
    ///      MANAGEMENT key still reverts same guard as a direct {removeKey}.
    function _uninstallModule(uint256 moduleTypeId, address module, bytes memory deInitData) internal virtual override {
        super._uninstallModule(moduleTypeId, module, deInitData);

        bytes32 moduleKey = keccak256(abi.encodePacked(module));
        KeyStorage storage ks = _getKeyStorage();
        // Modules installed without a purpose (purpose == 0 on the ModuleInstall entry)
        // have no key entry, so nothing to clean up.
        if (ks.keys[moduleKey].key == bytes32(0)) return;

        // Snapshot the purposes before iterating: `_removeKeyPurpose` mutates the set.
        uint256[] memory purposes = ks.keys[moduleKey].purposes.values();
        for (uint256 i = 0; i < purposes.length; i++) {
            _removeKeyPurpose(moduleKey, purposes[i]);
        }
    }

    /**
     * @notice Override of OZ's `executeFromExecutor` that enforces the same ERC-734 purpose
     *         rule used for UserOps. The executor's address is registered as a key at install
     *         time; this function checks that key against the targets in the executionCalldata.
     */
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        public
        payable
        virtual
        override
        returns (bytes[] memory returnData)
    {
        // 1. Caller must be a registered executor module.
        require(
            isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender, Calldata.emptyBytes()),
            Errors.ExecutorPurposeNotAuthorized()
        );

        // 2. Treat the executor's address as an ERC-734 key — its purpose was granted at install time.
        bytes32 callerKeyHash = keccak256(abi.encodePacked(msg.sender));
        // 3. Run the same per-target purpose rule used for UserOps.
        if (!_isAuthorizedForExecution(mode, executionCalldata, callerKeyHash)) {
            revert Errors.ExecutorPurposeNotAuthorized();
        }

        // 4. Hand off to OZ's batch/single dispatcher.
        return _execute(Mode.wrap(mode), executionCalldata);
    }

    /**
     * @notice ERC-1271 signature validation. ACTION purpose required on the recovered signer.
     *
     * @param hashToVerify The 32-byte digest the user claims to have signed off-chain.
     * @param signature Layout: `address module (20 bytes) || abi.encode(bytes signer, bytes sig)`.
     * @return ERC-1271 magic value on success, `_SIG_INVALID` (0xffffffff) on any failure.
     *         MUST never revert.
     */
    function isValidSignature(bytes32 hashToVerify, bytes calldata signature)
        public
        view
        virtual
        override
        returns (bytes4)
    {
        // ACTION is the 1271 minimum: an off-chain signature represents intent to act on the account.
        return _isValidSignature(hashToVerify, signature, KeyPurposes.ACTION)
            ? IERC1271.isValidSignature.selector
            : _SIG_INVALID;
    }

    /**
     * @dev Shared signature-validation core used by {isValidSignature} and {Identity.isClaimValid}.
     *      Single source of truth for "is this signature valid for this account given a required
     *      purpose."
     *
     *      Routes through the installed ERC-7579 validator module named in the first 20 bytes
     *      of the signature. The recovered signer must hold `requiredPurpose` on this account.
     *      Wrapped against reverts so it returns `false` instead of bubbling.
     */
    function _isValidSignature(bytes32 hash, bytes calldata sig, uint256 requiredPurpose) internal view returns (bool) {
        // 1. Length guard — the module address prefix is 20 bytes.
        if (sig.length < 20) return false;

        // 2. Split prefix and inner signature; the prefix names the validator module to dispatch through.
        (address module, bytes calldata moduleSignature) = _extractSignatureValidator(sig);
        // 3. Reject signatures that name an unknown / uninstalled validator.
        if (!isModuleInstalled(MODULE_TYPE_VALIDATOR, module, Calldata.emptyBytes())) return false;

        // 4. Recover the declared signer key. Wrapped via a self-staticcall so a malformed
        //    `abi.encode(bytes signer, bytes sig)` yields false instead of reverting.
        bytes32 signerKeyHash;
        try this._extractKeyHash(moduleSignature) returns (bytes32 keyHash) {
            signerKeyHash = keyHash;
        } catch {
            return false;
        }
        // 5. Enforce the caller-requested purpose (CLAIM_SIGNER for claims, ACTION for 1271).
        if (!keyHasPurpose(signerKeyHash, requiredPurpose)) return false;

        // 6. Delegate the crypto check to the validator module. Try-wrapped — any revert ⇒ false.
        try IERC7579Validator(module).isValidSignatureWithSender(msg.sender, hash, moduleSignature) returns (
            bytes4 magicValue
        ) {
            return magicValue == IERC1271.isValidSignature.selector;
        } catch {
            return false;
        }
    }

    /// @dev External-only because it's invoked via `this.` from {_isValidSignature} to wrap
    ///      `abi.decode` in a try/catch. Solidity does not allow try/catch on internal calls.
    function _extractKeyHash(bytes calldata moduleSignature) external pure returns (bytes32) {
        (bytes memory signerBytes,) = abi.decode(moduleSignature, (bytes, bytes));
        return keccak256(signerBytes);
    }

    /**
     * @notice ERC-4337 UserOperation validation. Called by the EntryPoint before execution.
     *
     * @dev Three gates: module installed, signer registered, signer authorized for the call.
     *      Only after all three pass do we delegate the crypto check to the validator module.
     *      MUST NOT revert — reverts here trigger UserOp rejection at the bundler level.
     */
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        virtual
        override
        returns (uint256)
    {
        // Gate 1: validator module named in `userOp.nonce`'s key field must be installed.
        address module = _extractUserOpValidator(userOp);
        if (!isModuleInstalled(MODULE_TYPE_VALIDATOR, module, Calldata.emptyBytes())) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        // Gate 2: declared signer must be registered as a key on this account.
        (bytes memory signerBytes,) = abi.decode(signature, (bytes, bytes));
        bytes32 signerKeyHash = keccak256(signerBytes);
        if (_getKeyStorage().keys[signerKeyHash].key == bytes32(0)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        // Gate 3: signer's purpose must cover every target in the userOp's executionCalldata.
        if (!_isAuthorizedForUserOpCallData(userOp.callData, signerKeyHash)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        // All gates pass — delegate the actual crypto verification to the validator module.
        return IERC7579Validator(module).validateUserOp(userOp, _signableUserOpHash(userOp, userOpHash));
    }

    /// @dev Decodes the outer `execute(mode, executionCalldata)` call and delegates to the
    ///      shared per-target check. Re-enters via `this.` so the inner executionCalldata stays
    ///      as `bytes calldata` and `_isAuthorizedForExecution` can use `ERC7579Utils.decodeBatch`
    ///      (avoiding a memory copy of the batch array).
    function _isAuthorizedForUserOpCallData(bytes calldata callData, bytes32 signerKeyHash)
        private
        view
        returns (bool)
    {
        // Reject any callData not addressed to our single `execute(mode, executionCalldata)` entry.
        if (callData.length < 4 || bytes4(callData[:4]) != AccountERC7579Upgradeable.execute.selector) {
            return false;
        }
        // Unpack the outer execute() args. `executionCalldata` lands in memory (Solidity rule).
        (bytes32 mode, bytes memory executionCalldata) = abi.decode(callData[4:], (bytes32, bytes));
        // Re-enter via `this.` to flip `executionCalldata` back to calldata — lets the inner
        // function use `ERC7579Utils.decodeBatch` (no memory copy) and gives us a free try/catch.
        try this._isAuthorizedForExecutionExternal(mode, executionCalldata, signerKeyHash) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev External-only re-entry point so the `bytes memory` executionCalldata flips back to
    ///      `bytes calldata` when this function executes. Called only via `this.` from
    ///      `_isAuthorizedForUserOpCallData`.
    function _isAuthorizedForExecutionExternal(bytes32 modeWord, bytes calldata executionCalldata, bytes32 keyHash)
        external
        view
        returns (bool)
    {
        require(msg.sender == address(this));
        return _isAuthorizedForExecution(modeWord, executionCalldata, keyHash);
    }

    /**
     * @dev The single authorization rule for "is this key allowed to dispatch this execution."
     *      Used by both `_validateUserOp` (after decoding the UserOp callData) and
     *      `executeFromExecutor` (with the executor's address-as-key). SINGLE and BATCH
     *      supported; DELEGATECALL and unknown modes rejected.
     */
    function _isAuthorizedForExecution(bytes32 modeWord, bytes calldata executionCalldata, bytes32 keyHash)
        internal
        view
        virtual
        returns (bool)
    {
        (CallType callType,,,) = ERC7579Utils.decodeMode(Mode.wrap(modeWord));

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // SINGLE layout: target(20) || value(32) || data(var). Read the first 20 bytes as the target.
            if (executionCalldata.length < 20) return false;
            return _isKeyAuthorizedToCallTarget(keyHash, address(bytes20(executionCalldata[:20])));
        }

        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            Execution[] calldata batch = ERC7579Utils.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                if (!_isKeyAuthorizedToCallTarget(keyHash, batch[i].target)) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    /// @dev Self-target ⇒ MANAGEMENT required; external target ⇒ ACTION required.
    function _isKeyAuthorizedToCallTarget(bytes32 keyHash, address target) private view returns (bool) {
        uint256 requiredPurpose = target == address(this) ? KeyPurposes.MANAGEMENT : KeyPurposes.ACTION;
        return keyHasPurpose(keyHash, requiredPurpose);
    }

}
