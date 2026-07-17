// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {
    IERC7579Execution,
    IERC7579Module,
    IERC7579ModuleConfig,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import { IERC734 } from "../../interface/IERC734.sol";
import { IERC735 } from "../../interface/IERC735.sol";
import { Errors } from "../../libraries/Errors.sol";
import { hashAddress } from "../../libraries/Hashing.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";

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
 *         Auto-approval rules (unchanged by the propose gate):
 *         - MANAGEMENT: anything.
 *         - ACTION: external targets only.
 *         - CLAIM_SIGNER on self: only `addClaim` / `removeClaim`.
 *         - CLAIM_ADDER on self: only `addClaim`.
 */
contract KeyApprovalModule is IERC7579Module {

    /// @dev Per-identity queue state. One slot per installing account.
    struct AccountState {
        uint256 executionNonce;
        mapping(uint256 => Execution) executions;
    }

    /// @dev A queued (and possibly already-run) execution request.
    struct Execution {
        address to;
        uint256 value;
        bytes data;
        bool approved;
        bool executed;
    }

    /// @dev Storage shared across all identities that install this module singleton.
    mapping(address => AccountState) private _state;

    /// @dev Emitted when an identity queues an execution via {execute}.
    event ExecutionRequested(
        address indexed account, uint256 indexed executionId, address indexed to, uint256 value, bytes data
    );

    /// @dev Emitted when an execution is approved (or rejected) via {approve}.
    event Approved(address indexed account, uint256 indexed executionId, bool approved);

    /// @dev Emitted when an approved execution successfully dispatches through the account.
    event Executed(address indexed account, uint256 indexed executionId, address indexed to, uint256 value, bytes data);

    /// @dev Emitted when an approved execution reverts inside the account.
    event ExecutionFailed(
        address indexed account, uint256 indexed executionId, address indexed to, uint256 value, bytes data
    );

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) public pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR || moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @inheritdoc IERC7579Module
    function onInstall(bytes calldata) external pure { }

    /// @inheritdoc IERC7579Module
    function onUninstall(bytes calldata) external pure { }

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
        state.executions[executionId] =
            Execution({ to: _to, value: _value, data: _data, approved: false, executed: false });

        emit ExecutionRequested(account, executionId, _to, _value, _data);

        // 3. Auto-approve dispatches now; otherwise the request stays pending for {approve}.
        if (_canAutoApprove(account, callerKeyHash, _to, _data)) {
            _runApproved(account, executionId);
        }
    }

    /// @notice Approve (or reject) a queued execution. Self-targeted calls require MANAGEMENT;
    ///         external targets require ACTION.
    function approve(uint256 _id, bool _shouldApprove) external returns (bool success) {
        // 1. Resolve account + ERC-2771 caller, fetch the queued request.
        address account = msg.sender;
        bytes32 callerKeyHash = hashAddress(_msgSender());
        AccountState storage state = _state[account];
        Execution storage execution = state.executions[_id];

        // 2. Sanity-check the request id and that it isn't already executed.
        require(_id < state.executionNonce, Errors.InvalidRequestId());
        require(!execution.executed, Errors.RequestAlreadyExecuted());

        // 3. Authorize the approver. Self-call ⇒ MANAGEMENT; external target ⇒ ACTION.
        // OZ `ERC7579Utils._call` rewrites `to == address(0)` to the account before dispatch,
        // so a queued `to=0` request runs as a self-call. Match that here before branching.
        address executionTo = execution.to == address(0) ? account : execution.to;
        if (executionTo == account) {
            require(
                IERC734(account).keyHasPurpose(callerKeyHash, KeyPurposes.MANAGEMENT),
                Errors.SenderDoesNotHaveManagementKey()
            );
        } else {
            require(
                IERC734(account).keyHasPurpose(callerKeyHash, KeyPurposes.ACTION), Errors.SenderDoesNotHaveActionKey()
            );
        }

        emit Approved(account, _id, _shouldApprove);

        // 4. Approval ⇒ dispatch now. Rejection ⇒ mark closed and exit.
        if (_shouldApprove) {
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

    /// @notice External view of the auto-approval rule. Lets the calling account reuse this
    ///         table see {SmartAccount._isKeyAuthorizedToCallTarget}.
    /// @dev    `account` must equal `msg.sender`: only an identity can ask about its own rule.
    function canAutoApprove(address account, bytes32 keyHash, address target, bytes calldata data)
        external
        view
        returns (bool)
    {
        require(account == msg.sender, Errors.UnauthorizedPolicyQuery());
        return _canAutoApprove(account, keyHash, target, data);
    }

    /// @dev Auto-approval policy. See contract NatSpec for the rule table.
    function _canAutoApprove(address account, bytes32 keyHash, address to, bytes calldata data)
        internal
        view
        returns (bool)
    {
        // OZ rewrites to 0 to the account before dispatch, so treat it as a self-call.
        if (to == address(0)) to = account;

        // MANAGEMENT keys pass any check.
        if (IERC734(account).keyHasPurpose(keyHash, KeyPurposes.MANAGEMENT)) {
            return true;
        }

        // Never auto-approve a call into one of the account's own modules (the account blocks it
        // too): an installed executor, or the fallback handler for this selector. Ask the account's
        // standard module config so this stays in step. bytes4(data) zero-pads short calldata.
        IERC7579ModuleConfig cfg = IERC7579ModuleConfig(account);
        bool toIsOwnModule = cfg.isModuleInstalled(MODULE_TYPE_EXECUTOR, to, "")
            || cfg.isModuleInstalled(MODULE_TYPE_FALLBACK, to, abi.encodePacked(bytes4(data)));
        if (to != account && toIsOwnModule) {
            return false;
        }

        // Self-targeted calls: only claim-related selectors auto-approve for claim keys.
        if (to == account && data.length >= 4) {
            bytes4 selector = bytes4(data);
            bool isAddClaim = selector == IERC735.addClaim.selector;
            bool isRemoveClaim = selector == IERC735.removeClaim.selector;

            if (IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER) && (isAddClaim || isRemoveClaim)) {
                return true;
            }
            if (IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_ADDER) && isAddClaim) {
                return true;
            }
            return false;
        }

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
    function _msgSender() internal view returns (address sender) {
        if (msg.data.length >= 20) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

}
