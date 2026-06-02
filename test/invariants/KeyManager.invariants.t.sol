// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Identity } from "contracts/Identity.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Stateful invariant suite for the ERC-734 key registry. Goal: hold a small set of
///         system-level properties across any sequence of `addKey`/`removeKey` calls. Config
///         is intentionally low (foundry.toml `[profile.default.invariant] runs=16 depth=16`)
///         to keep the default test suite fast; ramp via `FOUNDRY_PROFILE=ci` for audit runs.
contract KeyManagerInvariants is OnchainIDSetup {

    KeyManagerHandler internal handler;

    function setUp() public override {
        super.setUp();
        handler = new KeyManagerHandler(aliceIdentity, alice);
        // Only the handler's address is fuzzed against; this keeps the search space tight.
        targetContract(address(handler));
        // Restrict to the two interesting mutators so the runner doesn't waste depth on
        // `pure` getters that can't change state.
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = KeyManagerHandler.handler_addKey.selector;
        selectors[1] = KeyManagerHandler.handler_removeKey.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

    /// @notice at least one MANAGEMENT key must always exist. The contract enforces this
    ///         via the `CannotRemoveLastManagementKey` revert in `_removeKeyPurpose`; this
    ///         invariant verifies the rule survives every reachable add/remove sequence.
    function invariant_managementKeyAlwaysExists() public view {
        assertGe(aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 1);
    }

    /// @notice Registry consistency: for every (key, purpose) the handler has touched, the
    ///         flag returned by `keyHasPurpose(key, purpose)` must agree with the key's
    ///         presence in `getKeysByPurpose(purpose)`. Catches any divergence between the
    ///         two views of the same state.
    function invariant_keyHasPurposeAgreesWithKeysByPurpose() public view {
        bytes32[] memory tracked = handler.trackedKeys();
        uint256[] memory purposes = handler.allPurposes();

        for (uint256 i = 0; i < tracked.length; i++) {
            for (uint256 j = 0; j < purposes.length; j++) {
                bytes32 key = tracked[i];
                uint256 purpose = purposes[j];

                bytes32[] memory keysWithPurpose = aliceIdentity.getKeysByPurpose(purpose);
                bool keyInSet = false;
                for (uint256 k = 0; k < keysWithPurpose.length; k++) {
                    if (keysWithPurpose[k] == key) {
                        keyInSet = true;
                        break;
                    }
                }

                // `keyHasPurpose` also returns true via the MANAGEMENT universal rule
                // (KeyManager.sol:121). Strip that out: if the key holds the literal `purpose`
                // it must be in the `keysByPurpose[purpose]` set, and vice versa.
                uint256[] memory keyPurposes = aliceIdentity.getKeyPurposes(key);
                bool keyHasLiteralPurpose = false;
                for (uint256 k = 0; k < keyPurposes.length; k++) {
                    if (keyPurposes[k] == purpose) {
                        keyHasLiteralPurpose = true;
                        break;
                    }
                }

                assertEq(keyInSet, keyHasLiteralPurpose, "key/purpose set disagreement");
            }
        }
    }

    /// @notice Universal-MANAGEMENT rule (KeyManager.sol:121): a MANAGEMENT key answers
    ///         `keyHasPurpose(_, P) == true` for every purpose. Confirms that rule holds
    ///         across arbitrary registry mutations.
    function invariant_managementKeyHasEveryPurpose() public view {
        bytes32[] memory mgmtKeys = aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT);
        uint256[] memory purposes = handler.allPurposes();
        for (uint256 i = 0; i < mgmtKeys.length; i++) {
            for (uint256 j = 0; j < purposes.length; j++) {
                assertTrue(
                    aliceIdentity.keyHasPurpose(mgmtKeys[i], purposes[j]),
                    "MANAGEMENT key must answer keyHasPurpose true for every purpose"
                );
            }
        }
    }

}

/// @notice Invariant handler: drives the registry through bounded add/remove sequences.
///         Bounded inputs (small key pool, valid purpose range) keep the runner exploring
///         meaningful state transitions rather than burning runs on rejected inputs.
contract KeyManagerHandler is Test {

    Identity internal immutable identity;
    address internal immutable owner;

    /// @dev Small fixed pool — keeps the state space small so a low `depth` still explores
    ///      meaningful interactions (re-add, re-remove, multi-purpose keys).
    bytes32[] internal _keys;

    /// @dev Purposes 1..5 from `KeyPurposes`.
    uint256[] internal _purposes;

    constructor(Identity _id, address _owner) {
        identity = _id;
        owner = _owner;

        for (uint256 i = 0; i < 6; i++) {
            _keys.push(keccak256(abi.encodePacked("inv-key-", i)));
        }
        _purposes.push(KeyPurposes.MANAGEMENT);
        _purposes.push(KeyPurposes.ACTION);
        _purposes.push(KeyPurposes.CLAIM_SIGNER);
        _purposes.push(KeyPurposes.ENCRYPTION);
        _purposes.push(KeyPurposes.CLAIM_ADDER);
    }

    /// @notice Try to add a (key, purpose) pair. Failures are swallowed — the invariant suite
    ///         is interested in what reachable state the contract gets into, not in whether
    ///         every individual call succeeds. `fail_on_revert = false` in foundry.toml
    ///         covers most cases; the try/catch is extra defense for nested external calls.
    function handler_addKey(uint256 keyIdx, uint256 purposeIdx) public {
        keyIdx = bound(keyIdx, 0, _keys.length - 1);
        purposeIdx = bound(purposeIdx, 0, _purposes.length - 1);

        vm.prank(owner);
        try identity.addKey(_keys[keyIdx], _purposes[purposeIdx], KeyTypes.ECDSA) { } catch { }
    }

    function handler_removeKey(uint256 keyIdx, uint256 purposeIdx) public {
        keyIdx = bound(keyIdx, 0, _keys.length - 1);
        purposeIdx = bound(purposeIdx, 0, _purposes.length - 1);

        vm.prank(owner);
        try identity.removeKey(_keys[keyIdx], _purposes[purposeIdx]) { } catch { }
    }

    function trackedKeys() external view returns (bytes32[] memory) {
        return _keys;
    }

    function allPurposes() external view returns (uint256[] memory) {
        return _purposes;
    }

}
