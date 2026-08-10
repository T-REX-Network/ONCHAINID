// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice Regression tests for the KeyApprovalModule `approve` authorization gate.
///
///         The module is installed as an executor holding a MANAGEMENT key on the identity. Three
///         surfaces decide whether a queued call may run, and all three must treat management-grade
///         targets as such: the user-op validator (ERC734Validator._targetAllowed), auto-approval
///         (_canAutoApprove), and {approve}. Management-grade targets are the account itself, its
///         factory (wallet-binding calls), and the key registry (addKey/removeKey rewrite the
///         account's own key set). Before the fix, `approve` and `_canAutoApprove` authorized every
///         non-self external target with ACTION, so an ACTION key could push a queued `revokeAccount`
///         (terminal) or an `addKey(MANAGEMENT)` on the registry, dispatched under the module's key.
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

    /// @notice The enshrined key registry is management-grade. Its address is known to the account
    ///         even when the registry is not installed as an executor, so the own-module block
    ///         cannot be relied on; the classification must cover it directly.
    function test_isManagementTarget_coversRegistry() public view {
        address registry = aliceIdentity.registryModule();
        assertTrue(aliceIdentity.isManagementTarget(registry), "registry must be management-grade");
    }

    /// @notice An ACTION key cannot escalate through the queue by calling `addKey(MANAGEMENT)` on
    ///         the registry: auto-approval refuses it, and an ACTION approver is rejected. Without
    ///         the fix this granted the caller a MANAGEMENT key under the module's key.
    function test_approve_registryAddKey_rejectedForActionKey() public {
        address registry = aliceIdentity.registryModule();
        address attacker = makeAddr("registryAttacker");
        bytes32 attackerKeyHash = keccak256(abi.encodePacked(attacker));

        // addKey(signerData, clientData, purpose, keyType) writes under msg.sender == account.
        bytes memory call = abi.encodeWithSignature(
            "addKey(bytes,bytes,uint256,uint256)",
            abi.encodePacked(attacker),
            bytes(""),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA
        );

        // david is ACTION: queue the registry call. It must not auto-run.
        vm.prank(david);
        uint256 id = IKeyExecutor(address(aliceIdentity)).execute(registry, 0, call);

        KeyApprovalModule.Execution memory queued =
            onchainidSetup.keyApprovalModule.getExecutionData(address(aliceIdentity), id);
        assertFalse(queued.executed, "registry call must not auto-run for an ACTION key");

        // ACTION approver is rejected: the registry is management-grade.
        vm.prank(david);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IKeyExecutor(address(aliceIdentity)).approve(id, true);

        // No MANAGEMENT key was granted to the attacker.
        assertFalse(
            IERC734(address(aliceIdentity)).keyHasPurpose(attackerKeyHash, KeyPurposes.MANAGEMENT),
            "attacker must not hold MANAGEMENT"
        );
    }

    /// @dev Module list that reproduces the finding's deployment: KeyApprovalModule as an executor
    ///      (holding MANAGEMENT) plus the registry as a validator and ERC-734 getter fallback, but
    ///      WITHOUT the registry installed as an executor. That missing entry is the only thing that
    ///      made SmartAccount._authorizeCall's own-module block catch a registry-targeted call, so
    ///      this set removes the accidental protection and leaves only the KeyApprovalModule gate.
    function _modulesWithoutRegistryExecutor() internal view returns (Structs.ModuleInstall[] memory installs) {
        address kam = address(onchainidSetup.keyApprovalModule);
        address registry = address(onchainidSetup.signatureValidator);

        installs = new Structs.ModuleInstall[](7);
        installs[0] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_VALIDATOR, module: registry, initData: "", purpose: 0 });
        installs[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: kam, initData: "", purpose: KeyPurposes.MANAGEMENT
        });
        installs[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: kam,
            initData: abi.encodePacked(IKeyExecutor.execute.selector),
            purpose: 0
        });
        installs[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: kam,
            initData: abi.encodePacked(IKeyExecutor.approve.selector),
            purpose: 0
        });
        installs[4] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: kam,
            initData: abi.encodePacked(IKeyExecutor.getCurrentNonce.selector),
            purpose: 0
        });
        // Registry getter fallback so the factory's post-deploy MANAGEMENT-key check can be answered.
        installs[5] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: registry,
            initData: abi.encodePacked(IERC734.keyHasPurpose.selector),
            purpose: 0
        });
        installs[6] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: registry,
            initData: abi.encodePacked(IERC734.getKeysByPurpose.selector),
            purpose: 0
        });
    }

    /// @notice The finding's exact scenario: with the registry NOT installed as an executor (so the
    ///         own-module block does not fire for it), an ACTION key still cannot escalate through
    ///         the queue. The fix lives in the KeyApprovalModule gate, not in the accidental block.
    function test_approve_registryAddKey_blockedEvenWithoutOwnModuleProtection() public {
        (address owner,) = makeAddrAndKey("vulnOwner");
        address attacker = makeAddr("vulnAttacker");
        bytes32 attackerKeyHash = keccak256(abi.encodePacked(attacker));

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(owner)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(owner),
            clientData: ""
        });

        vm.prank(deployer);
        address idAddr = onchainidSetup.idFactory
            .createIdentityFor(
                owner, IdentityTypes.INDIVIDUAL, "vulnerable-config", keys, _modulesWithoutRegistryExecutor()
            );
        Identity id = Identity(payable(idAddr));
        address registry = id.registryModule();

        // Owner adds the attacker as an ACTION key.
        vm.prank(owner);
        id.addKeyWithData(attackerKeyHash, KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(attacker), "");

        // The registry is management-grade even though it is not an installed executor here.
        assertTrue(id.isManagementTarget(registry), "registry must be management-grade");

        bytes memory call = abi.encodeWithSignature(
            "addKey(bytes,bytes,uint256,uint256)",
            abi.encodePacked(attacker),
            bytes(""),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA
        );

        // Attacker (ACTION) queues the registry call: it must not auto-run.
        vm.prank(attacker);
        uint256 execId = IKeyExecutor(idAddr).execute(registry, 0, call);
        KeyApprovalModule.Execution memory queued = onchainidSetup.keyApprovalModule.getExecutionData(idAddr, execId);
        assertFalse(queued.executed, "registry call must not auto-run for an ACTION key");

        // And the ACTION approver is rejected by the module gate, not the own-module block.
        vm.prank(attacker);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IKeyExecutor(idAddr).approve(execId, true);

        assertFalse(
            IERC734(idAddr).keyHasPurpose(attackerKeyHash, KeyPurposes.MANAGEMENT),
            "attacker must not have escalated to MANAGEMENT"
        );
    }

}
