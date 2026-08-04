// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";

/// @notice Regression tests for the KeyApprovalModule `approve` authorization gate.
///
///         The module is installed as an executor holding a MANAGEMENT key on the identity. Three
///         surfaces decide whether a queued factory call may run, and all three must treat the
///         factory as management-grade: the user-op validator (ERC734Validator._targetAllowed),
///         auto-approval (_canAutoApprove), and {approve}. Before the fix, `approve` authorized
///         every non-self external target with ACTION, so the factory (an ordinary external target
///         from its point of view) let an ACTION key push through a queued `revokeAccount` under
///         the module's MANAGEMENT key. Revocation is terminal.
contract KeyApprovalModuleFactoryGuardTest is OnchainIDSetup {

    /// @dev alice's own management wallet, ERC-7913 EVM envelope, as linked by `createIdentityFor`.
    function _aliceWalletEnvelope() internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, alice);
    }

    /// @notice An ACTION key cannot approve a queued factory `revokeAccount`: the factory is now
    ///         management-grade on the approve path, so the terminal revocation is refused.
    function test_approve_factoryRevoke_rejectedForActionKey() public {
        bytes memory account = _aliceWalletEnvelope();
        bytes memory call = abi.encodeCall(IIdentityFactory.revokeAccount, (account));
        address factory = address(onchainidSetup.idFactory);

        // carol is CLAIM_SIGNER: enough to queue, never enough to auto-run a factory call.
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(factory, 0, call);

        // Auto-approval refused (carol is not MANAGEMENT and the target is the factory).
        KeyApprovalModule.Execution memory queued =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertFalse(queued.executed, "factory call must not auto-run for a non-MANAGEMENT proposer");

        // david is ACTION: previously enough to approve this external target, now rejected.
        vm.prank(david);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);

        // The wallet is still linked: the terminal revocation never happened.
        assertEq(
            onchainidSetup.idFactory.getIdentity(account), address(aliceIdentity), "alice wallet must remain linked"
        );
    }

    /// @notice A MANAGEMENT key still approves a queued factory `revokeAccount` — the legitimate
    ///         path is unchanged, only the ACTION shortcut is closed.
    function test_approve_factoryRevoke_allowedForManagementKey() public {
        bytes memory account = _aliceWalletEnvelope();
        bytes memory call = abi.encodeCall(IIdentityFactory.revokeAccount, (account));
        address factory = address(onchainidSetup.idFactory);

        // Queue via carol (CLAIM_SIGNER can propose but not auto-run a factory call).
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(factory, 0, call);

        // alice is MANAGEMENT: approval dispatches the revoke.
        vm.prank(alice);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);

        assertEq(onchainidSetup.idFactory.getIdentity(account), address(0), "management approval revokes the wallet");
    }

    /// @notice A queued call that targets one of the identity's own modules does NOT escalate:
    ///         SmartAccount refuses to dispatch into its own executor/fallback modules, so the
    ///         request fails at dispatch and is marked executed without running. This is the
    ///         distinction from the factory case — the factory is an external contract not on the
    ///         module list, which is why it needed the explicit approve-path guard.
    function test_approve_ownModuleTarget_blockedAtDispatch() public {
        address kam = address(onchainidSetup.keyApprovalModule);

        // Queue a call whose target is the KeyApprovalModule itself (an installed executor).
        vm.prank(carol);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(kam, 0, abi.encodeWithSignature("getCurrentNonce()"));

        // An ACTION key can approve an ordinary external target, but the account blocks the
        // dispatch into its own module, so the request is closed without ever running.
        vm.prank(david);
        bool ran = IKeyExecutor(address(aliceIdentity)).approve(id, true);

        assertFalse(ran, "dispatch into an own module must fail, not succeed");
        KeyApprovalModule.Execution memory queued =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertTrue(queued.executed, "request is closed after the failed dispatch");
    }

}
