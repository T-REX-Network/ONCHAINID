// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { KeyManager } from "./KeyManager.sol";
import { IKeyExecutor } from "./interface/IKeyExecutor.sol";
import { Errors } from "./libraries/Errors.sol";
import { hashAddress } from "./libraries/Hashing.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";
import { KeyApprovalModule } from "./modules/executors/KeyApprovalModule.sol";
import { LowLevelCall } from "./vendor/utils/LowLevelCall.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { Execution, MODULE_TYPE_EXECUTOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Calldata } from "@openzeppelin/contracts/utils/Calldata.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title SmartAccount
/// @notice ERC-7579 modular account that uses the ERC-734 key registry from {KeyManager}.
///         Signature checks happen in the installed validator; the per-target rule for
///         user ops runs here.
abstract contract SmartAccount is KeyManager, AccountERC7579Upgradeable, EIP712 {

    using EnumerableSet for EnumerableSet.UintSet;

    /// @notice Install a module. MANAGEMENT-gated so the factory can install at bootstrap.
    /// @dev The OZ default gate (`onlyEntryPointOrSelf`) is intentionally replaced with the
    ///      stricter ERC-734 `onlyManager` check, and `_installModule` is invoked directly
    ///      instead of `super.installModule`. This is required by the factory-orchestrated
    ///      bootstrap model: {IdentityFactory._setupIdentity} holds a transient MANAGEMENT
    ///      key on the freshly deployed identity and installs modules before any ERC-4337
    ///      EntryPoint or self-call path exists. The translated gate (`onlyManager` =
    ///      caller must hold a MANAGEMENT key in this identity's ERC-734 registry) is at
    ///      least as strict as the OZ default, because the only paths that satisfied
    ///      `onlyEntryPointOrSelf` were (a) the canonical EntryPoint, which in turn ran a
    ///      MANAGEMENT-key-signed UserOp, or (b) the identity calling itself, which can
    ///      only be reached via a MANAGEMENT-authorized executor. Closing issue #6 as
    ///      "won't fix" per design: the bootstrap path requires this override; the
    ///      override is documented and proven equivalent in privilege.
    /// @dev Fallback handler wiring: `module` must be a contract. If it resolves to an
    ///      EOA (or any non-zero address with no code), policy queries hit the strict
    ///      default and the fallback silently degrades. Don't install fallbacks on EOAs.
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        virtual
        override
        delegatedOnly
        onlyManager
    {
        _installModule(moduleTypeId, module, initData);
    }

    /// @notice Uninstall a module. MANAGEMENT-gated.
    /// @dev See {installModule} for the rationale behind replacing the OZ default
    ///      `onlyEntryPointOrSelf` gate with `onlyManager` and bypassing `super`.
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        virtual
        override
        delegatedOnly
        onlyManager
    {
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    /// @dev Runs the base uninstall, then strips every ERC-734 purpose held by the
    ///      module's address so a reinstall doesn't keep old rights.
    function _uninstallModule(uint256 moduleTypeId, address module, bytes memory deInitData) internal virtual override {
        // Base uninstall (calls module's onUninstall).
        super._uninstallModule(moduleTypeId, module, deInitData);

        // Look up the module's key entry.
        bytes32 moduleKey = hashAddress(module);
        KeyStorage storage ks = _getKeyStorage();

        // No purpose was ever granted → nothing to clean up.
        if (ks.keys[moduleKey].key == bytes32(0)) return;

        // Snapshot purposes before iterating (the set mutates during removal).
        uint256[] memory purposes = ks.keys[moduleKey].purposes.values();
        for (uint256 i = 0; i < purposes.length; i++) {
            _removeKeyPurpose(moduleKey, purposes[i]);
        }
    }

    /// @notice Executor entry point. Applies the per-target rule, then defers to super
    ///         (which enforces the executor-module modifier and dispatches the call).
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        public
        payable
        virtual
        override
        returns (bytes[] memory)
    {
        // Use the executor's address as the key for the purpose lookup.
        bytes32 callerKeyHash = hashAddress(msg.sender);

        // Apply the same per-target rule used for user ops.
        if (!_isAuthorizedForExecution(mode, executionCalldata, callerKeyHash)) {
            revert Errors.ExecutorPurposeNotAuthorized();
        }

        // Super handles the executor-module check (onlyModule modifier) and dispatch.
        return super.executeFromExecutor(mode, executionCalldata);
    }

    /// @notice ERC-4337 user op validation. Validator proves the signature, then this
    ///         function applies the per-target rule.
    /// @dev The second decode of `(signer, sig)` is intentional. The validator decoded
    ///      it for crypto; we decode it again to read the signer for policy.
    ///      Validator contract: installed validators MUST use `abi.encode(bytes signer,
    ///      bytes sig)` and MUST bind `signer` to verification. Otherwise the keyhash
    ///      we derive here can diverge from the identity the validator actually checked.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        virtual
        override
        returns (uint256)
    {
        // Step 1: let the installed validator prove the signature + ACTION purpose.
        // Validators can return a non-zero packed `validationData` that still means success
        // (encoded time bounds, or an aggregator authorizer). Only stop on the literal
        // failure code; otherwise the per-target rule must still run.
        uint256 baseValidation = super._validateUserOp(userOp, userOpHash, signature);
        if (baseValidation == ERC4337Utils.SIG_VALIDATION_FAILED) return baseValidation;

        // Step 2: read the signer. Safe to trust now: the validator just proved it.
        // Malformed payload reverts here; EntryPoint treats that as a failed user op.
        (bytes memory signer,) = abi.decode(signature, (bytes, bytes));
        bytes32 signerKeyHash = keccak256(signer);

        // Step 3: per-target rule.
        if (!_isAuthorizedForUserOpCallData(userOp.callData, signerKeyHash)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }
        // Returning `SIG_VALIDATION_SUCCESS` here would strip the time bounds and
        // aggregator the validator encoded above. Pass the original word through so
        // the EntryPoint enforces those constraints.
        return baseValidation;
    }

    /// @dev Unpacks the outer `execute(mode, data)` and forwards to `_isAuthorizedForExecution`.
    ///      Bounces through `this.` so the inner calldata stays as `calldata` (no memory copy).
    function _isAuthorizedForUserOpCallData(bytes calldata callData, bytes32 signerKeyHash)
        private
        view
        returns (bool)
    {
        // Only the standard execute() selector is accepted.
        if (callData.length < 4 || bytes4(callData[:4]) != AccountERC7579Upgradeable.execute.selector) {
            return false;
        }

        // Decode the outer execute() args.
        uint256 dataOffset = uint256(bytes32(callData[0x24:0x44]));
        uint256 lenPos = 4 + dataOffset;
        uint256 dataStart = lenPos + 0x20;
        if (dataStart > callData.length) return false;
        uint256 dataLen = uint256(bytes32(callData[lenPos:]));
        if (dataStart + dataLen > callData.length) return false;
        return
            _isAuthorizedForExecution(bytes32(callData[4:0x24]), callData[dataStart:dataStart + dataLen], signerKeyHash);
    }

    /// @dev Per-target authorization. Shared by user ops and executor dispatch.
    ///      Supports SINGLE and BATCH; rejects DELEGATECALL and unknown modes.
    function _isAuthorizedForExecution(bytes32 modeWord, bytes calldata executionCalldata, bytes32 keyHash)
        internal
        view
        virtual
        returns (bool)
    {
        (CallType callType,,,) = ERC7579Utils.decodeMode(Mode.wrap(modeWord));

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // SINGLE executionCalldata layout:
            //   bytes [0 .. 20)  : target (an Ethereum address, 20 bytes)
            //   bytes [20 .. 52) : value  (a uint256, 32 bytes)
            //   bytes [52 ..   ) : data   (the inner ABI-encoded call: selector + args)
            // A well-formed payload is at least 52 bytes. Anything shorter is malformed.
            if (executionCalldata.length < 52) return false;
            address target = address(bytes20(executionCalldata[:20]));
            return _isKeyAuthorizedToCallTarget(keyHash, target, executionCalldata[52:]);
        }

        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            // Every call in the batch must pass.
            Execution[] calldata batch = ERC7579Utils.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                if (!_isKeyAuthorizedToCallTarget(keyHash, batch[i].target, batch[i].callData)) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    /// @dev Asks the installed policy module (KeyApprovalModule). If no policy is installed,
    ///      or the policy reverts, we apply a simple built-in rule instead:
    ///        - if the call targets THIS account (e.g. addKey, removeKey): require MANAGEMENT.
    ///        - if the call targets any OTHER address (external token, etc.): require ACTION.
    ///      This built-in rule is what we call the "strict default": it is intentionally
    ///      conservative, so an account with no policy installed still cannot be hijacked
    ///      into self-modifying calls by a plain ACTION key.
    function _isKeyAuthorizedToCallTarget(bytes32 keyHash, address target, bytes calldata data)
        private
        view
        returns (bool)
    {
        // OZ `ERC7579Utils._call` rewrites `target == address(0)` to `address(this)` before
        // dispatch, so a payload with target=0 lands as a self-call. Collapse the same alias
        // here so this self-vs-external check sees what the call will actually hit.
        if (target == address(0)) target = address(this);

        // Installed fallback/executor modules trust the ERC-2771 trailing bytes appended
        // by `_fallback()`. A direct call here skips that append, so the caller can forge
        // the tail. Require MANAGEMENT. Legitimate use goes through fallback/executor dispatch.
        if (
            isModuleInstalled(MODULE_TYPE_EXECUTOR, target, Calldata.emptyBytes())
                || (data.length >= 4 && _fallbackHandler(bytes4(data[:4])) == target)
        ) {
            return keyHasPurpose(keyHash, KeyPurposes.MANAGEMENT);
        }

        // The policy module is whichever contract is wired as the `execute` fallback handler.
        address policy = _fallbackHandler(IKeyExecutor.execute.selector);

        if (policy != address(0)) {
            // LowLevelCall so a broken policy can't brick the account.
            (bool success, bytes32 result,) = LowLevelCall.staticcallReturn64Bytes(
                policy, abi.encodeCall(KeyApprovalModule.canAutoApprove, (address(this), keyHash, target, data))
            );
            if (success && LowLevelCall.returnDataSize() == 32 && result == bytes32(uint256(1))) {
                return true;
            }
        }

        // Built-in rule (the "strict default"):
        //   self-target  -> MANAGEMENT required
        //   anything else -> ACTION required
        uint256 requiredPurpose = target == address(this) ? KeyPurposes.MANAGEMENT : KeyPurposes.ACTION;
        return keyHasPurpose(keyHash, requiredPurpose);
    }

}
