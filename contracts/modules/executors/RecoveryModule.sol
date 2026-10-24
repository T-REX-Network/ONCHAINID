// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.28;

import {
    ERC7579SocialRecoveryExecutor
} from "@openzeppelin/accounts/modules/executors/ERC7579SocialRecoveryExecutor.sol";

/// @title RecoveryModule
/// @notice Social recovery for ONCHAINID identities. Wraps OZ's
///         {ERC7579SocialRecoveryExecutor} (vendored via soldeer from
///         OpenZeppelin/openzeppelin-accounts, commit 4ceb836d). The guardian,
///         delay, and execution rules live upstream.
///
/// @dev    Why a wrapper.
///         The upstream contract is marked `abstract`, so we can't deploy it
///         directly. Inheriting it gives us a concrete contract we can instantiate
///         with `new RecoveryModule()` and a stable name for scripts and tests.
///         The override below is the ONCHAINID rule: a recovery can execute only
///         in the installation that scheduled it.
///
/// @dev    Why OZ instead of writing our own.
///         The recovery flow holds authority that can replace MANAGEMENT keys, so
///         writing our own means owning the audit. OZ already built the M-of-N +
///         delay + cancel design we want and pointed us at this file. We pin to
///         a commit so an upstream change can't surprise us. The pinned commit is
///         the post-fix state of OZ's audit of this module.
///
/// @dev    How an account uses it.
///         A MANAGEMENT key holder installs this as an ERC-7579 executor module
///         and registers the module address in {KeyManager} with the MANAGEMENT
///         purpose. That second step is the ONCHAINID-specific bit: without it,
///         {SmartAccount} would reject the self-targeted `addKey` call the
///         module dispatches at execution time. Same pattern KeyApprovalModule
///         uses.
///
///         Install data is OZ's length-prefixed format documented on
///         `ERC7579SocialRecoveryExecutor.onInstall`:
///             [uint16(execLen), execArgs, uint16(msigLen), msigArgs]
///         where:
///             execArgs = abi.encodePacked(uint32 delay, uint32 expiration)
///             msigArgs = abi.encode(bytes[] guardians, uint64 threshold, uint64[] weights)
///
/// @dev    How the identity cancels and reconfigures.
///         The owner path of `cancelRecovery` and the setters for guardians,
///         threshold, weights, delay and expiration only accept the account
///         as caller. To reach them, the account calls `execute` on itself
///         with an inner `execute` that targets this module. The outer call
///         needs MANAGEMENT like any self-targeted execution, and the inner
///         call is allowed because {SmartAccount} lets the account call its
///         own modules. Guardians keep their own quorum-signed
///         `cancelRecovery` path.
///
/// @dev    What recovery actually does.
///         `executeRecovery` dispatches whatever ERC-7579 execution the guardians
///         signed. The canonical recovery payload is a self-targeted
///         `addKeyWithData(newKey, MANAGEMENT, ECDSA, ...)`, which installs a
///         fresh MANAGEMENT key on the identity. The integration tests in
///         test/modules/recovery/RecoveryModule.t.sol exercise that round-trip
///         and show the recovered key works the same as the original for every
///         MANAGEMENT-gated operation.
///
/// @dev    Why this works with our Identity.
///         OZ's module scopes signatures to the account's EIP-712 domain by
///         calling `IERC5267(account).eip712Domain()`. {Identity} inherits OZ's
///         {EIP712}, which exposes that interface. Nothing extra to wire. Since
///         4ceb836d the typed data also commits to the module address, so a
///         guardian bundle is bound to one identity and one module deployment.
///         The module is a shared singleton: each account keeps its own guardian
///         set, threshold and schedule in module storage keyed by account.
contract RecoveryModule is ERC7579SocialRecoveryExecutor {

    error RecoveryCleanupNotInProgress(address account);

    /// @notice Guardian cleanup could not finish during account uninstall. The old
    ///         operation generation was still retired. The account can call
    ///         `onUninstall` directly with more gas to finish cleanup before reinstall.
    event RecoveryCleanupIncomplete(address indexed account);

    uint256 private constant _CLEANUP_GAS_RESERVE = 50_000;
    uint256 private constant _MIN_GAS_FOR_CLEANUP = 100_000;

    /// @dev One generation per account. Install and uninstall both advance it, and
    ///      the operation id commits to the value. A schedule from an earlier
    ///      installation then no longer addresses a known operation. The first
    ///      install moves the counter from 0 to 1. Accounts do not share it.
    ///      This lives on the module, so shipping it means a new module address.
    ///      The previous deployment keeps its own storage.
    mapping(address account => uint256 generation) private _generation;
    mapping(address account => bool inProgress) private _cleanupInProgress;

    /// @dev Record this installation, then advance the account's generation.
    ///      `msg.sender` is the account. A revert from the upstream install
    ///      rolls the increment back with it.
    function onInstall(bytes calldata data) public override {
        super.onInstall(data);
        ++_generation[msg.sender];
    }

    /// @dev Retire the generation before the potentially unbounded guardian cleanup.
    ///      The account implementation deliberately ignores a reverting module
    ///      callback. Running the cleanup in a bounded delegatecall lets this outer
    ///      call return successfully even if cleanup runs out of gas, so the retired
    ///      generation is not rolled back. Delegatecall preserves the account as
    ///      `msg.sender` for the upstream cleanup logic.
    function onUninstall(bytes calldata) public override {
        address account = msg.sender;
        ++_generation[account];

        if (gasleft() < _MIN_GAS_FOR_CLEANUP) {
            emit RecoveryCleanupIncomplete(account);
            return;
        }

        _cleanupInProgress[account] = true;
        (bool success,) = address(this).delegatecall{ gas: gasleft() - _CLEANUP_GAS_RESERVE }(
            abi.encodeCall(this.cleanupAfterUninstall, (bytes("")))
        );
        _cleanupInProgress[account] = false;
        if (!success) emit RecoveryCleanupIncomplete(account);
    }

    /// @dev Called only by `onUninstall` through delegatecall. A direct call must
    ///      not clear guardians without first moving the operation generation.
    function cleanupAfterUninstall(bytes calldata data) external {
        require(_cleanupInProgress[msg.sender], RecoveryCleanupNotInProgress(msg.sender));
        super.onUninstall(data);
    }

    /// @dev The upstream id, plus this account's current generation. Schedule,
    ///      execute, cancel, and `state` all call this, so they agree.
    function hashOperation(address account, bytes32 salt, bytes32 mode, bytes memory executionCalldata)
        public
        view
        override
        returns (bytes32)
    {
        return keccak256(abi.encode(account, salt, mode, executionCalldata, _generation[account]));
    }

}
