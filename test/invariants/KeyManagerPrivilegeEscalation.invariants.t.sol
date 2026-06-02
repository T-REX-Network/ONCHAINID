// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Identity } from "contracts/Identity.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Stateful access-control invariant for the ERC-734 key registry: a caller that does
///         NOT hold a MANAGEMENT key can never escalate any key — least of all its own — to
///         MANAGEMENT (purpose `1`) on an identity.
///
///         The sibling suite ({KeyManagerInvariants}) only ever pranks as `alice`, an
///         authorized manager, so it exercises state *consistency* under authorized mutation
///         but never the access-control boundary. This suite is the dual: it drives the
///         registry's three mutators (`addKey`, `addKeyWithData`, `removeKey`) from
///         *unauthorized* callers and asserts the privilege boundary holds across any
///         reachable call sequence. The guarantee under test is the `onlyManager` modifier in
///         `KeyManager.sol` — a non-MANAGEMENT caller's `addKey`/`removeKey` must always revert.
///
///         Setup reuses {OnchainIDSetup}: `aliceIdentity` has `alice` as a MANAGEMENT key,
///         `carol` holding only CLAIM_SIGNER, and `david` holding only ACTION — i.e. real keys
///         that hold *some* purpose but not MANAGEMENT, the realistic escalation scenario.
///         Config follows the [profile.default.invariant] in foundry.toml (`runs=16 depth=16`)
///         to keep `forge test` fast; ramp via `FOUNDRY_PROFILE=ci` for audit runs.
contract KeyManagerPrivilegeEscalationInvariants is OnchainIDSetup {

    PrivilegeEscalationHandler internal handler;
    bytes32 internal aliceKeyHash;

    /// @dev Baseline MANAGEMENT key set captured after setup, before any handler call. Note the
    ///      identity legitimately starts with TWO MANAGEMENT keys: `alice` and the auto-installed
    ///      {KeyApprovalModule} (granted MANAGEMENT via `legacyQueueModules`). The invariant is
    ///      that a non-manager can neither grow nor shrink this exact set.
    bytes32[] internal initialMgmt;

    function setUp() public override {
        super.setUp();
        aliceKeyHash = keccak256(abi.encodePacked(alice));

        bytes32[] memory mgmt = aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT);
        for (uint256 i = 0; i < mgmt.length; i++) {
            initialMgmt.push(mgmt[i]);
        }

        // Non-MANAGEMENT callers: carol (CLAIM_SIGNER) + david (ACTION) hold real but
        // unprivileged keys; eve + mallory hold no key at all. None should ever reach MANAGEMENT.
        address[] memory attackers = new address[](4);
        attackers[0] = carol;
        attackers[1] = david;
        attackers[2] = makeAddr("esc-eve");
        attackers[3] = makeAddr("esc-mallory");

        handler = new PrivilegeEscalationHandler(aliceIdentity, attackers, aliceKeyHash);
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = PrivilegeEscalationHandler.handler_selfGrantManagement.selector;
        selectors[1] = PrivilegeEscalationHandler.handler_selfGrantManagementWithData.selector;
        selectors[2] = PrivilegeEscalationHandler.handler_grantManagementToTarget.selector;
        selectors[3] = PrivilegeEscalationHandler.handler_removeAliceManagement.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

    /// @notice ESC1: the MANAGEMENT key set never changes from its captured baseline. Catches
    ///         both directions of escalation: a non-manager minting a new MANAGEMENT key (set
    ///         grows) and a non-manager stripping an existing manager (set shrinks). Equal length
    ///         plus subset membership (it is a set, no duplicates) proves set equality.
    function invariant_managementSetUnchanged() public view {
        bytes32[] memory mgmt = aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT);
        assertEq(mgmt.length, initialMgmt.length, "a non-management caller created or removed a MANAGEMENT key");
        for (uint256 i = 0; i < mgmt.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < initialMgmt.length; j++) {
                if (mgmt[i] == initialMgmt[j]) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "MANAGEMENT set gained a key not present in the baseline");
        }
    }

    /// @notice ESC2: no non-management caller's own key ever answers `keyHasPurpose(_, MANAGEMENT)`.
    ///         This is the literal "a non-manager cannot make itself purpose `1`" check, keyed by
    ///         exactly the hash `onlyManager` derives from `msg.sender`
    ///         (`keccak256(abi.encodePacked(caller))`).
    function invariant_attackersNeverHoldManagement() public view {
        address[] memory attackers = handler.attackers();
        for (uint256 i = 0; i < attackers.length; i++) {
            assertFalse(
                aliceIdentity.keyHasPurpose(keccak256(abi.encodePacked(attackers[i])), KeyPurposes.MANAGEMENT),
                "a non-management caller escalated its own key to MANAGEMENT"
            );
        }
    }

    /// @notice ESC3: no key the handler attempted to escalate ever gains MANAGEMENT.
    function invariant_targetsNeverGainManagement() public view {
        bytes32[] memory targets = handler.escalationTargets();
        for (uint256 i = 0; i < targets.length; i++) {
            assertFalse(
                aliceIdentity.keyHasPurpose(targets[i], KeyPurposes.MANAGEMENT),
                "a non-management caller granted MANAGEMENT to a target key"
            );
        }
    }

    /// @notice Guards against a vacuous pass: if selector wiring broke and the handler never ran
    ///         a single escalation attempt, the invariants above would pass trivially. Assert the
    ///         handler actually exercised the boundary.
    function afterInvariant() public view {
        assertGt(handler.attempts(), 0, "no escalation attempts were exercised");
    }

}

/// @notice Drives privilege-escalation attempts from non-MANAGEMENT callers. Every mutator pranks
///         as an unprivileged address and tries to reach MANAGEMENT through one of the registry's
///         write paths. All calls are expected to revert via `onlyManager`; the `try/catch`
///         swallows the revert so the fuzzer keeps exploring, and the suite's invariants assert
///         that no escalation slipped through regardless of which path was taken.
contract PrivilegeEscalationHandler is Test {

    Identity internal immutable identity;
    bytes32 internal immutable _aliceKeyHash;

    /// @dev Unprivileged callers that must never reach MANAGEMENT.
    address[] internal _attackers;

    /// @dev Key hashes the handler tries to push MANAGEMENT onto: each attacker's own hash plus
    ///      a couple of arbitrary "victim" hashes that no one is authorized to mint.
    bytes32[] internal _targets;

    /// @notice Number of escalation attempts driven so far (ghost counter for `afterInvariant`).
    uint256 public attempts;

    constructor(Identity _id, address[] memory attackers_, bytes32 aliceKeyHash_) {
        identity = _id;
        _aliceKeyHash = aliceKeyHash_;

        for (uint256 i = 0; i < attackers_.length; i++) {
            _attackers.push(attackers_[i]);
            // An attacker's most direct escalation target is its own key hash.
            _targets.push(keccak256(abi.encodePacked(attackers_[i])));
        }
        _targets.push(keccak256("esc-victim-0"));
        _targets.push(keccak256("esc-victim-1"));
    }

    /// @notice Attacker tries to grant MANAGEMENT to its own key hash via `addKey`.
    function handler_selfGrantManagement(uint256 aIdx) public {
        address a = _attackers[bound(aIdx, 0, _attackers.length - 1)];
        attempts++;
        vm.prank(a);
        try identity.addKey(keccak256(abi.encodePacked(a)), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA) { } catch { }
    }

    /// @notice Same, but through the `addKeyWithData` entry point (signerData commits to the hash).
    function handler_selfGrantManagementWithData(uint256 aIdx) public {
        address a = _attackers[bound(aIdx, 0, _attackers.length - 1)];
        attempts++;
        vm.prank(a);
        try identity.addKeyWithData(
            keccak256(abi.encodePacked(a)), KeyPurposes.MANAGEMENT, KeyTypes.ECDSA, abi.encodePacked(a), ""
        ) { }
            catch { }
    }

    /// @notice Attacker tries to grant MANAGEMENT to an arbitrary target key.
    function handler_grantManagementToTarget(uint256 aIdx, uint256 tIdx) public {
        address a = _attackers[bound(aIdx, 0, _attackers.length - 1)];
        bytes32 target = _targets[bound(tIdx, 0, _targets.length - 1)];
        attempts++;
        vm.prank(a);
        try identity.addKey(target, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA) { } catch { }
    }

    /// @notice Attacker tries to strip the legitimate manager — the other half of escalation
    ///         (removing the only authority that outranks it).
    function handler_removeAliceManagement(uint256 aIdx) public {
        address a = _attackers[bound(aIdx, 0, _attackers.length - 1)];
        attempts++;
        vm.prank(a);
        try identity.removeKey(_aliceKeyHash, KeyPurposes.MANAGEMENT) { } catch { }
    }

    function attackers() external view returns (address[] memory) {
        return _attackers;
    }

    function escalationTargets() external view returns (bytes32[] memory) {
        return _targets;
    }

}
