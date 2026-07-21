// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { KeyManager } from "./KeyManager.sol";
import { Errors } from "./libraries/Errors.sol";
import { hashAddress } from "./libraries/Hashing.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";
import { ERC734Validator } from "./modules/validators/ERC734Validator.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { Execution, MODULE_TYPE_EXECUTOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Calldata } from "@openzeppelin/contracts/utils/Calldata.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title SmartAccount
/// @notice ERC-7579 modular account that uses the ERC-734 key registry from {KeyManager}.
///         Signature checks happen in the installed validator; the per-target rule for
///         user ops runs here.
abstract contract SmartAccount is KeyManager, AccountERC7579Upgradeable, EIP712 {

    /// @notice Install a module. Gated on MANAGEMENT.
    /// @dev The OZ default gate (`onlyEntryPointOrSelf`) is replaced with the stricter
    ///      ERC-734 `onlyManagerOrSelf` check, and `_installModule` is invoked directly instead
    ///      of `super.installModule`. The translated gate is at least as strict as the
    ///      OZ default, because the only paths that satisfied `onlyEntryPointOrSelf` were
    ///      (a) the canonical EntryPoint, which in turn ran a MANAGEMENT-signed UserOp,
    ///      or (b) the identity calling itself, which can only be reached via a
    ///      MANAGEMENT-authorized executor. The override lets a MANAGEMENT key holder
    ///      install or rotate modules directly, without round-tripping through an
    ///      EntryPoint or a self-call. Closing issue #6 as "won't fix" per design.
    /// @dev Fallback handler wiring: `module` must be a contract. If it resolves to an
    ///      EOA (or any non-zero address with no code), policy queries hit the strict
    ///      default and the fallback silently degrades. Don't install fallbacks on EOAs.
    /// @dev Installing a validator hands it the job of authorizing user ops. The account does not
    ///      re-check a user op the validator accepted, so the validator's signers get whatever
    ///      authority the validator gives them. If a validator does not restrict its signers, they
    ///      can even reach self-modifying calls like addKey. So only install validators you trust to
    ///      scope their keys; the enshrined {ERC734Validator} does. This is not an escalation:
    ///      installing the validator in the first place already needs MANAGEMENT.
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        virtual
        override
        onlyManagerOrSelf
    {
        _installModule(moduleTypeId, module, initData);
    }

    /// @notice Uninstall a module. MANAGEMENT-gated.
    /// @dev See {installModule} for the rationale behind replacing the OZ default
    ///      `onlyEntryPointOrSelf` gate with `onlyManagerOrSelf` and bypassing `super`.
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        virtual
        override
        onlyManagerOrSelf
    {
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    /// @dev Strips every ERC-734 purpose the module holds, then runs the base uninstall.
    ///      Purposes are read from, and removed on, the enshrined registry module (self-calls).
    function _uninstallModule(uint256 moduleTypeId, address module, bytes memory deInitData) internal virtual override {
        // Take away the module's ERC-734 purposes first, then run the base uninstall (which calls
        // the module's onUninstall). Order matters: a module that still holds MANAGEMENT could use
        // its onUninstall callback to grant itself keys. Stripping first closes that window.
        bytes32 moduleKey = hashAddress(module);
        ERC734Validator registry = ERC734Validator(_registryModule());

        // Drop each purpose the module holds. Snapshot first, since the set shrinks as we remove.
        // At most the 6 ERC-734 purposes, so the loop is cheap. Skip if the module had no key.
        (bytes memory signerData,) = registry.getKeyData(address(this), moduleKey);
        if (signerData.length != 0) {
            uint256[] memory purposes = registry.getKeyPurposes(address(this), moduleKey);
            for (uint256 i = 0; i < purposes.length; i++) {
                _removeKeyPurpose(moduleKey, purposes[i]);
            }
        }

        super._uninstallModule(moduleTypeId, module, deInitData);
    }

    /// @notice The one place every dispatched call is authorized. Both `execute` (user ops and
    ///         MANAGEMENT self-calls) and {executeFromExecutor} go through here, so there is only one
    ///         authorization path to keep right. DELEGATECALL and unknown call types are rejected.
    function _execute(Mode mode, bytes calldata executionCalldata) internal virtual override returns (bytes[] memory) {
        // Work out who is calling: their key hash, and whether they are an installed executor
        // (which gets purpose-checked).
        bytes32 callerKeyHash = hashAddress(msg.sender);
        bool callerIsExecutor = isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender, Calldata.emptyBytes());

        (CallType callType,,,) = ERC7579Utils.decodeMode(mode);

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // SINGLE layout: target (20) | value (32) | data. A shorter payload is malformed;
            // reject it here so a call can never skip the guard below and reach super unauthorized.
            require(executionCalldata.length >= 52, Errors.UnsupportedExecutionMode(Mode.unwrap(mode)));
            address target = address(bytes20(executionCalldata[:20]));
            _authorizeCall(target, executionCalldata[52:], callerKeyHash, callerIsExecutor);
        } else if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            // Every call in the batch must pass.
            Execution[] calldata batch = ERC7579Utils.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                _authorizeCall(batch[i].target, batch[i].callData, callerKeyHash, callerIsExecutor);
            }
        } else {
            revert Errors.UnsupportedExecutionMode(Mode.unwrap(mode));
        }

        return super._execute(mode, executionCalldata);
    }

    /// @dev Authorizes one call: no dispatched call may target one of the account's own modules,
    ///      and an executor caller needs a key purpose for the target.
    function _authorizeCall(address target, bytes calldata inner, bytes32 callerKeyHash, bool callerIsExecutor)
        private
        view
    {
        // OZ rewrites target 0 to the account before dispatch; do the same so the checks agree.
        if (target == address(0)) target = address(this);

        // A dispatched call must never land on one of the account's own modules: an installed
        // executor, or the fallback handler for this call's selector. Module functions are reached
        // through the account's fallback dispatch, which appends the real caller (ERC-2771 style);
        // `execute(module, ...)` skips that append, so the module would misread its caller.
        // `bytes4(inner)` zero-pads short/empty calldata, which matches no handler.
        bool targetIsOwnModule = isModuleInstalled(MODULE_TYPE_EXECUTOR, target, Calldata.emptyBytes())
            || _fallbackHandler(bytes4(inner)) == target;
        if (targetIsOwnModule) {
            revert Errors.OwnModuleTargetBlocked(target);
        }

        // An executor's own key must have a purpose that authorizes this target.
        if (callerIsExecutor && !_isKeyAuthorizedToCallTarget(callerKeyHash, target)) {
            revert Errors.ExecutorPurposeNotAuthorized();
        }
    }

    /// @dev The purpose an executor's key needs for a target: self-target needs MANAGEMENT,
    ///      any other target needs ACTION. MANAGEMENT satisfies every purpose check.
    function _isKeyAuthorizedToCallTarget(bytes32 keyHash, address target) private view returns (bool) {
        uint256 requiredPurpose = target == address(this) ? KeyPurposes.MANAGEMENT : KeyPurposes.ACTION;
        return _moduleKeyHasPurpose(keyHash, requiredPurpose);
    }

}
