// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IKeyRegistryModule, KeyManager } from "./KeyManager.sol";
import { IKeyExecutor } from "./interface/IKeyExecutor.sol";
import { IOwnModule } from "./interface/IOwnModule.sol";
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

/// @title SmartAccount
/// @notice ERC-7579 modular account that uses the ERC-734 key registry from {KeyManager}.
///         Signature checks happen in the installed validator; the per-target rule for
///         user ops runs here.
abstract contract SmartAccount is KeyManager, AccountERC7579Upgradeable, EIP712, IOwnModule {

    /// @notice Install a module. Gated on MANAGEMENT.
    /// @dev The OZ default gate (`onlyEntryPointOrSelf`) is replaced with the stricter
    ///      ERC-734 `onlyManager` check, and `_installModule` is invoked directly instead
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
    ///      module's address so a reinstall doesn't keep old rights. Purposes are read from,
    ///      and removed on, the enshrined registry module (self-calls).
    function _uninstallModule(uint256 moduleTypeId, address module, bytes memory deInitData) internal virtual override {
        // Base uninstall (calls module's onUninstall).
        super._uninstallModule(moduleTypeId, module, deInitData);

        // Look up the module's key entry on the registry module.
        bytes32 moduleKey = hashAddress(module);
        IKeyRegistryModule registry = IKeyRegistryModule(_registryModule());

        // No key record for this module address → nothing to clean up.
        (bytes memory signerData,) = registry.getKeyData(address(this), moduleKey);
        if (signerData.length == 0) return;

        // Bounded to the 6 ERC-734 purposes, so this loop is cheap. Snapshot before iterating,
        // since the set mutates during removal.
        uint256[] memory purposes = registry.getKeyPurposes(address(this), moduleKey);
        for (uint256 i = 0; i < purposes.length; i++) {
            _removeKeyPurpose(moduleKey, purposes[i]);
        }
    }

    /// @notice The one place every dispatched call is authorized. Both `execute` (user ops and
    ///         MANAGEMENT self-calls) and {executeFromExecutor} go through here, so there is only one
    ///         authorization path to keep right. DELEGATECALL and unknown call types are rejected.
    function _execute(Mode mode, bytes calldata executionCalldata) internal virtual override returns (bytes[] memory) {
        // Work out who is calling: their key hash, whether they are an installed executor (which
        // gets purpose-checked), and whether they are privileged (the account, or a MANAGEMENT module).
        bytes32 callerKeyHash = hashAddress(msg.sender);
        bool callerIsExecutor = isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender, Calldata.emptyBytes());
        bool privilegedCaller =
            msg.sender == address(this) || _moduleKeyHasPurpose(callerKeyHash, KeyPurposes.MANAGEMENT);

        (CallType callType,,,) = ERC7579Utils.decodeMode(mode);

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // SINGLE layout: target (20) | value (32) | data. Anything shorter is malformed; let the
            // base dispatcher revert on it.
            if (executionCalldata.length >= 52) {
                address target = address(bytes20(executionCalldata[:20]));
                _authorizeCall(target, executionCalldata[52:], callerKeyHash, privilegedCaller, callerIsExecutor);
            }
        } else if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            // Every call in the batch must pass.
            Execution[] calldata batch = ERC7579Utils.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                _authorizeCall(batch[i].target, batch[i].callData, callerKeyHash, privilegedCaller, callerIsExecutor);
            }
        } else {
            revert Errors.UnsupportedExecutionMode(Mode.unwrap(mode));
        }

        return super._execute(mode, executionCalldata);
    }

    /// @inheritdoc IOwnModule
    /// @dev Kept in one place so the account and its modules agree on the answer. The account uses
    ///      it in its guard, and modules like {KeyApprovalModule} ask it instead of checking again.
    function isOwnModule(address target, bytes4 selector) public view virtual returns (bool) {
        return
            isModuleInstalled(MODULE_TYPE_EXECUTOR, target, Calldata.emptyBytes())
                || _fallbackHandler(selector) == target;
    }

    /// @dev Authorizes one call: block re-entry into the account's own modules, then, for an
    ///      executor caller, require its key to have a purpose for the target.
    function _authorizeCall(
        address target,
        bytes calldata inner,
        bytes32 callerKeyHash,
        bool privilegedCaller,
        bool callerIsExecutor
    ) private view {
        // OZ rewrites target 0 to the account before dispatch; do the same so the checks agree.
        if (target == address(0)) target = address(this);

        // Only a privileged caller may re-enter one of the account's own modules.
        // `bytes4(inner)` zero-pads short/empty calldata, which matches no handler.
        if (isOwnModule(target, bytes4(inner)) && !privilegedCaller) {
            revert Errors.PrivilegedTargetRequiresManagement(target);
        }

        // An executor's own key must have a purpose that authorizes this target.
        if (callerIsExecutor && !_isKeyAuthorizedToCallTarget(callerKeyHash, target, inner)) {
            revert Errors.ExecutorPurposeNotAuthorized();
        }
    }

    /// @notice ERC-4337 user op validation.
    /// @dev A pure pass-through. The installed validator verifies the signature and scopes the call;
    ///      the account stays agnostic to the signature format so any stock validator can be used.
    ///      Per-call authorization for the dispatch itself happens later, in {_execute}.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        virtual
        override
        returns (uint256)
    {
        return super._validateUserOp(userOp, userOpHash, signature);
    }

    /// @dev Decides the purpose an executor's key needs for a target. Asks the installed policy
    ///      module (KeyApprovalModule) first; if none is installed or it reverts, falls back to a
    ///      conservative rule: self-target needs MANAGEMENT, any other target needs ACTION.
    function _isKeyAuthorizedToCallTarget(bytes32 keyHash, address target, bytes calldata data)
        private
        view
        returns (bool)
    {
        // target is already self-aliased and re-entry-guarded by {_authorizeCall}.

        // The policy module is whatever contract handles the `execute` fallback selector.
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
        return _moduleKeyHasPurpose(keyHash, requiredPurpose);
    }

}
