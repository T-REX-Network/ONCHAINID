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

import { Errors } from "../../libraries/Errors.sol";
import {
    ERC7579SocialRecoveryExecutor
} from "@openzeppelin/accounts/modules/executors/ERC7579SocialRecoveryExecutor.sol";

/// @title RecoveryModule
/// @notice Social recovery for ONCHAINID identities. Wraps OZ's
///         {ERC7579SocialRecoveryExecutor} (vendored via soldeer from
///         OpenZeppelin/openzeppelin-accounts, commit 4ceb836d). Guardians, delay
///         and execution all live upstream. The one thing added here is an
///         install generation recorded on every schedule, so a recovery scheduled
///         under a previous installation cannot execute after a reinstall.
///
/// @dev    Why a wrapper.
///         The upstream contract is marked `abstract`, so we can't deploy it
///         directly. Inheriting it once gives us a concrete contract we can
///         instantiate with `new RecoveryModule()` and a stable name to reference
///         from scripts and tests.
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

    /// @dev Per-account install counter. OZ keeps scheduled operations across
    ///      uninstall on purpose, so without this a recovery scheduled under a
    ///      previous installation could still execute after the module is
    ///      reinstalled. While the module is uninstalled the account refuses its
    ///      dispatches, so advancing on install is enough.
    mapping(address account => uint256 generation) private _generation;

    /// @dev The generation each operation was scheduled under. Operation ids stay
    ///      OZ's: a guardian approval only commits to salt, mode and payload, so
    ///      changing the id per installation would let every past approval be
    ///      scheduled again after a reinstall. Keeping the id stable keeps each
    ///      approval single-use, and the generation check below does the rest.
    mapping(bytes32 operationId => uint256 generation) private _scheduledIn;

    function onInstall(bytes calldata data) public override {
        super.onInstall(data);
        ++_generation[msg.sender];
    }

    function _scheduleAt(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata,
        uint48 timepoint,
        uint32 delay
    ) internal override returns (bytes32 id) {
        id = super._scheduleAt(account, salt, mode, executionCalldata, timepoint, delay);
        _scheduledIn[id] = _generation[account];
    }

    /// @dev OZ's `state` is not virtual, so an operation from a previous installation
    ///      still reads as `Ready` there. Only this path decides whether it runs. The
    ///      account can still cancel it to tidy up.
    function _execute(address account, bytes32 salt, bytes32 mode, bytes memory executionCalldata)
        internal
        override
        returns (bytes[] memory)
    {
        bytes32 id = hashOperation(account, salt, mode, executionCalldata);
        require(_scheduledIn[id] == _generation[account], Errors.RecoveryScheduledUnderPreviousInstall(id));
        return super._execute(account, salt, mode, executionCalldata);
    }

}
