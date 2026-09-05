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
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import { IERC734 } from "../../interface/IERC734.sol";
import { IKeyExecutor } from "../../interface/IKeyExecutor.sol";
import { Errors } from "../../libraries/Errors.sol";
import { hashAddress } from "../../libraries/Hashing.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";

/// @dev Minimal view of the account: does a target need MANAGEMENT (self or factory)?
///      See {SmartAccount.isManagementTarget}.
interface IIdentityAccount {

    function isManagementTarget(address target) external view returns (bool);

}

/**
 * @title KeyApprovalModule
 * @notice Externalized ERC-734 `execute` / `approve` queue, served to identities via the
 *         ERC-7579 fallback handler + executor module pattern.
 *
 *         The account owns the key registry (`keyHasPurpose`); this module owns the execution
 *         queue and the auto-approval rules. Per-identity state is keyed by `account` because
 *         a single module deployment is shared across every identity that installs it.
 *
 *         Proposing vs auto-executing are separate gates. To queue a request via {execute}
 *         the caller must hold at least one of PROPOSER / ACTION / CLAIM_SIGNER /
 *         CLAIM_ADDER / MANAGEMENT on the identity. Random addresses cannot pollute the
 *         queue or the event log. PROPOSER is a queue-only purpose: it lets a key queue
 *         a request that then waits for an approver and never auto-runs by itself.
 *
 *         A queued request records the key that proposed it. Approving re-checks that key, so a
 *         request whose proposer was revoked can no longer be dispatched. Rejecting does not:
 *         any authorized approver can still close a stale entry.
 *
 *         Uninstalling the module (the executor or any of its fallback selectors) voids every
 *         request queued so far, so a pending queue cannot be resurrected across a reinstall.
 *
 *         Auto-approval rules (unchanged by the propose gate):
 *         - MANAGEMENT: anything.
 *         - ACTION: external targets only.
 *         - Anything else on self: never.
 *
 *         {execute} and {approve} only work when called through the account's ERC-7579 fallback,
 *         because that is what appends the caller for {_msgSender} to read. If the call arrives
 *         any other way, for example relayed by the EntryPoint or dispatched by the account
 *         itself, nothing is appended, so the recovered caller holds no key and the call is
 *         refused. To add or remove a claim on the identity itself, call that selector on the
 *         account directly instead of queueing it here.
 */
contract KeyApprovalModule is IERC7579Module, IKeyExecutor {

    /// @dev Per-identity queue state. One slot per installing account. Requests with an id
    ///      below `firstValidId` are void; {onUninstall} bumps the floor to the current nonce.
    struct AccountState {
        uint256 executionNonce;
        uint256 firstValidId;
        mapping(uint256 => Execution) executions;
    }

    /// @dev A queued (and possibly already-run) execution request.
    struct Execution {
        address to;
        uint256 value;
        bytes data;
        address proposer;
        bool approved;
        bool executed;
        // `executed` only says the request was attempted and is closed; it is set on a failed
        // dispatch and on a rejection too. This is the one that says the call actually landed.
        bool succeeded;
    }

    /// @dev Storage shared across all identities that install this module singleton.
    mapping(address => AccountState) private _state;

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) public pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR || moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @inheritdoc IERC7579Module
    function onInstall(bytes calldata) external pure { }

    /// @inheritdoc IERC7579Module
    /// @dev Voids every request queued so far by the uninstalling account. Runs on each
    ///      uninstall of this module (the executor or any fallback selector), so even a
    ///      partial teardown kills the queue. Fails closed: nothing here can revert.
    function onUninstall(bytes calldata) external {
        AccountState storage state = _state[msg.sender];
        uint256 nonce = state.executionNonce;
        if (state.firstValidId < nonce) {
            state.firstValidId = nonce;
            emit QueueInvalidated(msg.sender, nonce);
        }
    }

    /// @notice Queue an execution for the calling identity. Auto-runs if the caller's key
    ///         purpose authorizes it; otherwise waits for {approve}.
    /// @dev    Treasury model: any `msg.value` is pushed back to the identity; `_value` is
    ///         dispatched from the identity's balance when the request runs.
    ///         Gated: caller must hold a key on the identity that authorizes proposing.
    function execute(address _to, uint256 _value, bytes calldata _data) external payable returns (uint256 executionId) {
        address account = msg.sender;
        address proposer = _msgSender();
        bytes32 callerKeyHash = hashAddress(proposer);

        // Reject random callers. Any key with a real purpose on the identity can propose;
        // PROPOSER is the queue-only purpose for callers who should be able to push
        // requests but cannot auto-run or approve them.
        require(_canPropose(account, callerKeyHash), Errors.SenderCannotPropose(proposer));

        // 1. Push any msg.value back to the identity so the module never holds ETH.
        if (msg.value > 0) {
            (bool returned,) = account.call{ value: msg.value }("");
            require(returned, Errors.ReturnToAccountFailed());
        }

        // 2. Allocate the next execution id and persist the request.
        AccountState storage state = _state[account];
        executionId = state.executionNonce++;
        state.executions[executionId] = Execution({
            to: _to, value: _value, data: _data, proposer: proposer, approved: false, executed: false, succeeded: false
        });

        emit ExecutionRequested(account, executionId, _to, _value, _data, proposer);

        // 3. Auto-approve dispatches now; otherwise the request stays pending for {approve}.
        if (_canAutoApprove(account, callerKeyHash, _to)) {
            _runApproved(account, executionId);
        }
    }

    /// @notice Approve (or reject) a queued execution. Management-grade targets (the account, its
    ///         factory, or the key registry) require MANAGEMENT; other external targets require ACTION.
    /// @dev    This gate is target-level (MANAGEMENT vs ACTION). Per-selector claim granularity (e.g.
    ///         addClaim needing only CLAIM_SIGNER) is handled by the claim branch in `_canAutoApprove`
    ///         and the account's fallback dispatch, not here.
    function approve(uint256 _id, bool _shouldApprove) external returns (bool success) {
        // 1. Resolve account + ERC-2771 caller, fetch the queued request.
        address account = msg.sender;
        address approver = _msgSender();
        bytes32 callerKeyHash = hashAddress(approver);
        AccountState storage state = _state[account];
        Execution storage execution = state.executions[_id];

        // 2. Sanity-check the request id, that it wasn't voided by an uninstall, and that
        //    it isn't already executed.
        require(_id < state.executionNonce, Errors.InvalidRequestId());
        require(_id >= state.firstValidId, Errors.RequestInvalidated());
        require(!execution.executed, Errors.RequestAlreadyExecuted());

        // 3. Authorize the approver. A management-grade target (the account, its factory, or the
        // key registry) needs MANAGEMENT; other external targets need ACTION. Without this, an ACTION
        // key could approve a queued factory call (e.g. terminally revoke a wallet) or a registry
        // call (e.g. grant itself a MANAGEMENT key), dispatched under the module's MANAGEMENT key.
        if (IIdentityAccount(account).isManagementTarget(execution.to)) {
            require(
                IERC734(account).keyHasPurpose(callerKeyHash, KeyPurposes.MANAGEMENT),
                Errors.SenderDoesNotHaveManagementKey()
            );
        } else {
            require(
                IERC734(account).keyHasPurpose(callerKeyHash, KeyPurposes.ACTION), Errors.SenderDoesNotHaveActionKey()
            );
        }

        emit Approved(account, _id, _shouldApprove, approver);

        // 4. Approval ⇒ the key that queued the request must still be able to propose, then
        //    dispatch now. A request whose proposer was revoked cannot run, but any authorized
        //    approver can still reject it and close the stale entry.
        if (_shouldApprove) {
            require(
                _canPropose(account, hashAddress(execution.proposer)),
                Errors.ProposerNoLongerAuthorized(execution.proposer)
            );
            return _runApproved(account, _id);
        }
        execution.executed = true;
        execution.approved = false;
        return false;
    }

    /// @notice Current execution nonce for the calling identity.
    function getCurrentNonce() external view returns (uint256) {
        return _state[msg.sender].executionNonce;
    }

    /// @notice Returns a queued execution by `account` and `executionId`.
    function getExecutionData(address account, uint256 executionId) external view returns (Execution memory) {
        return _state[account].executions[executionId];
    }

    /// @dev Auto-approval policy. See contract NatSpec for the rule table. Module targets are
    ///      not special-cased here: the account itself refuses to dispatch into its own modules
    ///      (see {SmartAccount}), so such a request just fails there and emits `ExecutionFailed`.
    function _canAutoApprove(address account, bytes32 keyHash, address to) internal view returns (bool) {
        // OZ rewrites to 0 to the account before dispatch, so treat it as a self-call.
        if (to == address(0)) to = account;

        // MANAGEMENT keys pass any check.
        if (IERC734(account).keyHasPurpose(keyHash, KeyPurposes.MANAGEMENT)) {
            return true;
        }

        // Self-targeted calls never auto-approve below MANAGEMENT. There used to be a rule here
        // letting claim keys auto-approve addClaim/removeClaim on self, but it could never work.
        // `_runApproved` dispatches through `executeFromExecutor`, so the account calls the claim
        // selector on itself and the fallback appends the account as the ERC-2771 caller. The
        // claim registry then looks for a claim key on the account, finds none, and reverts. The
        // try/catch turned that into a silent `ExecutionFailed`. Claim keys should call addClaim
        // or removeClaim on the account directly.
        if (to == account) return false;

        // A management-grade target (the factory or the key registry) never auto-approves for a
        // non-MANAGEMENT key; MANAGEMENT already returned above.
        if (IIdentityAccount(account).isManagementTarget(to)) return false;

        // External target: ACTION keys can dispatch directly.
        if (to != account && IERC734(account).keyHasPurpose(keyHash, KeyPurposes.ACTION)) return true;

        return false;
    }

    /// @dev Gate for {execute}. Any purpose that can already authorize an auto-run or an
    ///      approval also passes here, plus the queue-only PROPOSER purpose. MANAGEMENT is
    ///      implicit: `keyHasPurpose` returns true for a MANAGEMENT key on any queried purpose.
    function _canPropose(address account, bytes32 keyHash) internal view returns (bool) {
        IERC734 acct = IERC734(account);
        return acct.keyHasPurpose(keyHash, KeyPurposes.PROPOSER) || acct.keyHasPurpose(keyHash, KeyPurposes.ACTION)
            || acct.keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER)
            || acct.keyHasPurpose(keyHash, KeyPurposes.CLAIM_ADDER);
    }

    /// @dev Dispatches via `executeFromExecutor`, which spends `execution.value` from the
    ///      identity's balance. try/catch so a failed dispatch emits `ExecutionFailed`
    ///      instead of reverting.
    /// @dev `executed`/`approved` are written before the dispatch on purpose: they are what stops
    ///      the target re-entering {approve} on the same id. They therefore cannot double as a
    ///      success flag, so the outcome is recorded separately in `succeeded`.
    function _runApproved(address account, uint256 executionId) internal returns (bool success) {
        Execution storage execution = _state[account].executions[executionId];

        execution.executed = true;
        execution.approved = true;

        address to = execution.to;
        uint256 value = execution.value;
        bytes memory data = execution.data;

        // CALLTYPE_SINGLE + EXECTYPE_DEFAULT: all-zero mode word.
        bytes32 mode = bytes32(0);
        bytes memory executionCalldata = abi.encodePacked(to, value, data);

        try IERC7579Execution(account).executeFromExecutor(mode, executionCalldata) returns (bytes[] memory) {
            execution.succeeded = true;
            emit Executed(account, executionId, to, value, data);
            return true;
        } catch {
            emit ExecutionFailed(account, executionId, to, value, data);
            return false;
        }
    }

    /// @dev Reached via the account's fallback, `msg.sender` is the account, so the real caller is
    ///      appended (ERC-2771 style) as the trailing 20 bytes; we read it from there.
    /// @dev We can trust that tail because {SmartAccount} blocks the only path that could forge it
    ///      (a direct call to this module, which arrives with no appended tail).
    /// @dev The length check only says a tail could fit, not that one was actually appended. On a
    ///      path that skips the fallback the last 20 bytes are just ABI arguments, so the caller
    ///      reads back as some address that holds no key and the call is refused. We ask for a
    ///      selector plus the tail, so a call too short to carry one uses `msg.sender` instead.
    function _msgSender() internal view returns (address sender) {
        if (msg.data.length >= 24) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

}
