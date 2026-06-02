// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

/// @notice Tests for Identity Key Management (ERC-734)
contract KeysTest is OnchainIDSetup {

    bytes32 public aliceKeyHash;
    bytes32 public bobKeyHash;

    function setUp() public override {
        super.setUp();

        aliceKeyHash = ClaimSignerHelper.addressToKey(alice);
        bobKeyHash = ClaimSignerHelper.addressToKey(bob);
    }

    // ============ Read key methods ============

    function test_RetrieveExistingKey() public view {
        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(aliceKeyHash);

        assertEq(key, aliceKeyHash);
        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_RetrieveExistingKeyPurposes() public view {
        uint256[] memory purposes = aliceIdentity.getKeyPurposes(aliceKeyHash);

        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
    }

    function test_RetrieveExistingKeysWithGivenPurpose() public view {
        bytes32[] memory keys = aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT);

        // Alice is one MANAGEMENT key; the auto-installed KeyApprovalModule is registered
        // as another (its address is hashed and stored as a key so that dispatches through
        // it are gated by the same ERC-734 purpose rule as any other key).
        bool aliceFound = false;
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i] == aliceKeyHash) {
                aliceFound = true;
                break;
            }
        }
        assertTrue(aliceFound, "alice should be a MANAGEMENT key");
    }

    function test_ReturnTrueIfKeyHasGivenPurpose() public view {
        bool hasPurpose = aliceIdentity.keyHasPurpose(aliceKeyHash, KeyPurposes.MANAGEMENT);

        assertTrue(hasPurpose);
    }

    function test_ReturnTrueIfKeyIsManagementKeyButNotGivenPurpose() public view {
        // MANAGEMENT keys have universal permissions, so they return true for any purpose
        bool hasPurpose = aliceIdentity.keyHasPurpose(aliceKeyHash, KeyPurposes.ACTION);

        assertTrue(hasPurpose);
    }

    function test_ReturnFalseIfKeyDoesNotHaveGivenPurpose() public view {
        bool hasPurpose = aliceIdentity.keyHasPurpose(bobKeyHash, KeyPurposes.ACTION);

        assertFalse(hasPurpose);
    }

    // ============ Add key methods - Non-Management key ============

    function test_RevertAddKey_WhenCallerIsNotManagementKey() public {
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        vm.prank(bob);
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
    }

    // ============ Add key methods - Management key ============

    function test_AddPurposeToExistingKey() public {
        vm.prank(alice);
        aliceIdentity.addKey(aliceKeyHash, KeyPurposes.ACTION, KeyTypes.ECDSA);

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(aliceKeyHash);

        assertEq(key, aliceKeyHash);
        assertEq(purposes.length, 2);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(purposes[1], KeyPurposes.ACTION);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_AddNewKeyWithPurpose() public {
        vm.prank(alice);
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(bobKeyHash);

        assertEq(key, bobKeyHash);
        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_RevertAddKey_WhenKeyAlreadyHasPurpose() public {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.KeyAlreadyHasPurpose.selector, aliceKeyHash, KeyPurposes.MANAGEMENT)
        );
        vm.prank(alice);
        aliceIdentity.addKey(aliceKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
    }

    /// @notice Re-purposing an existing key with a different `_type` is rejected.
    function test_RevertAddKey_WhenKeyTypeDoesNotMatchExisting() public {
        // aliceKeyHash already exists with keyType = ECDSA. Attempt to add a new purpose with RSA.
        vm.expectRevert(
            abi.encodeWithSelector(Errors.KeyTypeMismatch.selector, aliceKeyHash, KeyTypes.ECDSA, KeyTypes.RSA)
        );
        vm.prank(alice);
        aliceIdentity.addKey(aliceKeyHash, KeyPurposes.ACTION, KeyTypes.RSA);
    }

    // ============ Remove key methods - Non-Management key ============

    function test_RevertRemoveKey_WhenCallerIsNotManagementKey() public {
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        vm.prank(bob);
        aliceIdentity.removeKey(aliceKeyHash, KeyPurposes.MANAGEMENT);
    }

    // ============ Remove key methods - Management key ============

    function test_RemovePurposeFromExistingKey() public {
        // Removing the only MANAGEMENT key is forbidden. Add a second one first so the
        // invariant holds.
        vm.prank(alice);
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);

        vm.prank(alice);
        aliceIdentity.removeKey(aliceKeyHash, KeyPurposes.MANAGEMENT);

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(aliceKeyHash);

        assertEq(key, bytes32(0));
        assertEq(purposes.length, 0);
        assertEq(keyType, 0);
    }

    function test_RevertRemoveKey_WhenKeyDoesNotExist() public {
        vm.expectRevert(abi.encodeWithSelector(Errors.KeyNotRegistered.selector, bobKeyHash));
        vm.prank(alice);
        aliceIdentity.removeKey(bobKeyHash, KeyPurposes.ACTION);
    }

    function test_RevertRemoveKey_WhenKeyDoesNotHavePurpose() public {
        vm.expectRevert(abi.encodeWithSelector(Errors.KeyDoesNotHavePurpose.selector, aliceKeyHash, KeyPurposes.ACTION));
        vm.prank(alice);
        aliceIdentity.removeKey(aliceKeyHash, KeyPurposes.ACTION);
    }

    function test_RemoveKeyFromPurposeArray() public {
        // Add bob as MANAGEMENT + ACTION key
        vm.startPrank(alice);
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.ACTION, KeyTypes.ECDSA);

        // Remove MANAGEMENT purpose
        aliceIdentity.removeKey(bobKeyHash, KeyPurposes.MANAGEMENT);
        vm.stopPrank();

        // Verify the key still has ACTION purpose only
        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(bobKeyHash);

        assertEq(key, bobKeyHash);
        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.ACTION);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    // ============ Remove key - edge cases ============

    /// @notice Remove the only key for a given purpose
    function test_RemoveOnlyKeyForPurpose() public {
        // carol has CLAIM_SIGNER only on aliceIdentity (added in setUp)
        bytes32 carolKeyHash = ClaimSignerHelper.addressToKey(carol);

        // Remove carol's CLAIM_SIGNER purpose
        vm.prank(alice);
        aliceIdentity.removeKey(carolKeyHash, KeyPurposes.CLAIM_SIGNER);

        // Verify carol no longer has CLAIM_SIGNER purpose
        assertFalse(aliceIdentity.keyHasPurpose(carolKeyHash, KeyPurposes.CLAIM_SIGNER));
    }

    /// @notice Remove a key's only purpose — key should be fully deleted
    function test_RemoveKeyWithSinglePurpose() public {
        // david has ACTION only on aliceIdentity (added in setUp)
        bytes32 davidKeyHash = ClaimSignerHelper.addressToKey(david);

        // david has exactly one purpose (ACTION)
        uint256[] memory purposes = aliceIdentity.getKeyPurposes(davidKeyHash);
        assertEq(purposes.length, 1, "David should have exactly 1 purpose");

        // Remove ACTION purpose
        vm.prank(alice);
        aliceIdentity.removeKey(davidKeyHash, KeyPurposes.ACTION);

        // Key should be fully deleted
        (, uint256 keyType2, bytes32 key2) = aliceIdentity.getKey(davidKeyHash);
        assertEq(key2, bytes32(0), "Key should be deleted");
        assertEq(keyType2, 0, "Key type should be 0");
    }

    /// @notice C11: `addKeyWithData` reverts when keyHash and signerData don't match.
    ///         The invariant binds the registered keyHash to the stored signer bytes so
    ///         downstream readers can trust either field independently.
    function test_AddKeyWithData_revertsOnHashMismatch() public {
        bytes32 declaredHash = keccak256(abi.encodePacked(bob));
        bytes memory mismatchedSignerData = abi.encodePacked(carol);

        vm.prank(alice);
        vm.expectRevert(Errors.InvalidSignerData.selector);
        aliceIdentity.addKeyWithData(declaredHash, KeyPurposes.ACTION, KeyTypes.ECDSA, mismatchedSignerData, "");
    }

    /// @notice C11: `addKeyWithData` accepts the call when keyHash == keccak256(signerData).
    function test_AddKeyWithData_acceptsMatchingHash() public {
        bytes32 keyHash = keccak256(abi.encodePacked(bob));
        bytes memory signerData = abi.encodePacked(bob);

        vm.prank(alice);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.ACTION, KeyTypes.ECDSA, signerData, "");

        (, uint256 keyType, bytes32 storedKey) = aliceIdentity.getKey(keyHash);
        assertEq(storedKey, keyHash);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    /// @notice getKeyData returns the (signerData, clientData) tuple registered with the key.
    function test_getKeyData_returnsSignerAndClientData() public {
        bytes32 keyHash = keccak256(abi.encodePacked(bob));
        bytes memory signerData = abi.encodePacked(bob);
        bytes memory clientData = hex"deadbeef";

        vm.prank(alice);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.ACTION, KeyTypes.ECDSA, signerData, clientData);

        (bytes memory storedSigner, bytes memory storedClient) = aliceIdentity.getKeyData(keyHash);
        assertEq(storedSigner, signerData);
        assertEq(storedClient, clientData);
    }

    /// @notice getKeyData on an unknown key returns empty bytes for both fields.
    function test_getKeyData_unknownKey_returnsEmpty() public view {
        (bytes memory s, bytes memory c) = aliceIdentity.getKeyData(keccak256("never-registered"));
        assertEq(s.length, 0);
        assertEq(c.length, 0);
    }

    /// @notice Adding the same key with a different ECDSA purpose succeeds when type matches.
    function test_AddKey_samePurposeReverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.KeyAlreadyHasPurpose.selector, aliceKeyHash, KeyPurposes.MANAGEMENT)
        );
        aliceIdentity.addKey(aliceKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
    }

    /// @notice keyHasPurpose returns false for an unknown key.
    function test_keyHasPurpose_unknownKey_false() public view {
        assertFalse(aliceIdentity.keyHasPurpose(keccak256("unknown"), KeyPurposes.ACTION));
    }

    // ============ View-function edge cases (formerly Keys.branches.t.sol) ============

    bytes32 internal constant _UNKNOWN_KEY = keccak256("never-registered");

    function test_getKey_unknownKey_returnsEmptyTuple() public view {
        (uint256[] memory purposes, uint256 keyType, bytes32 key) = aliceIdentity.getKey(_UNKNOWN_KEY);
        assertEq(purposes.length, 0);
        assertEq(keyType, 0);
        assertEq(key, bytes32(0));
    }

    function test_getKeyPurposes_unknownKey_returnsEmpty() public view {
        uint256[] memory purposes = aliceIdentity.getKeyPurposes(_UNKNOWN_KEY);
        assertEq(purposes.length, 0);
    }

    /// @notice Purpose 9999 is not in `KeyPurposes`; no key has it; the set is empty.
    function test_getKeysByPurpose_unknownPurpose_returnsEmpty() public view {
        bytes32[] memory ids = aliceIdentity.getKeysByPurpose(9999);
        assertEq(ids.length, 0);
    }

    /// @notice MANAGEMENT key returns true for any purpose query thanks to the universal
    ///         permission rule at `KeyManager.sol:121`.
    function test_keyHasPurpose_mgmt_returnsTrueForAnyPurpose() public view {
        assertTrue(aliceIdentity.keyHasPurpose(aliceKeyHash, 9999), "MANAGEMENT must cover any purpose");
    }

    // ============ Identity.supportsInterface — all four advertised IDs and a negative ============

    function test_supportsInterface_erc165_true() public view {
        assertTrue(aliceIdentity.supportsInterface(type(IERC165).interfaceId));
    }

    function test_supportsInterface_erc734_true() public view {
        assertTrue(aliceIdentity.supportsInterface(type(IERC734).interfaceId));
    }

    function test_supportsInterface_erc735_true() public view {
        assertTrue(aliceIdentity.supportsInterface(type(IERC735).interfaceId));
    }

    function test_supportsInterface_iidentity_true() public view {
        assertTrue(aliceIdentity.supportsInterface(type(IIdentity).interfaceId));
    }

    /// @notice Unknown interface IDs return false (the catch-all `else` branch at the end of
    ///         `Identity.supportsInterface`). Picks a stable random selector unlikely to match.
    function test_supportsInterface_unknownInterface_false() public view {
        assertFalse(aliceIdentity.supportsInterface(bytes4(0xdeadbeef)));
    }

    /// @notice The ERC-165 selector itself is `0xffffffff` per spec — must return false.
    function test_supportsInterface_erc165InvalidSentinel_false() public view {
        assertFalse(aliceIdentity.supportsInterface(bytes4(0xffffffff)));
    }

    // ============ KeyManager storage layout + write-path correctness ============

    /// @notice Pins the canonical ERC-7201 storage namespace for `KeyManager`. The base slot
    ///         is `keccak256(uint256(keccak256("onchainid.keymanager.storage")) - 1) & ~0xff`.
    ///         Under that slot, offset +2 holds the packed `initialized || canInteract`
    ///         booleans (both true after init). If the namespace computation ever drifts to a
    ///         different slot (e.g. the `- 1` were replaced by another operator), state lives
    ///         at a different slot and this read returns zero — the test fails.
    function test_keyStorage_canonicalERC7201Slot_holdsInitBooleans() public view {
        bytes32 canonicalBase = keccak256(abi.encode(uint256(keccak256(bytes("onchainid.keymanager.storage"))) - 1))
            & ~bytes32(uint256(0xff));
        // Struct layout: slot 0 = `keys` mapping marker, slot 1 = `keysByPurpose` marker,
        // slot 2 = packed (bool initialized, bool canInteract). After init both are true.
        bytes32 initSlot = bytes32(uint256(canonicalBase) + 2);
        bytes32 raw = vm.load(address(aliceIdentity), initSlot);
        assertTrue(raw != bytes32(0), "canonical ERC-7201 slot+2 must hold non-zero init bits");
    }

    /// @notice Companion check — the slot a `... + 1`-namespaced variant would have produced
    ///         is empty. Together with the canonical-slot test above, this confirms storage
    ///         lives exactly at the ERC-7201-spec namespace and not at any neighboring offset.
    function test_keyStorage_offsetSlot_isEmpty() public view {
        bytes32 offsetBase = keccak256(abi.encode(uint256(keccak256(bytes("onchainid.keymanager.storage"))) + 1))
            & ~bytes32(uint256(0xff));
        bytes32 offsetInitSlot = bytes32(uint256(offsetBase) + 2);
        assertEq(
            vm.load(address(aliceIdentity), offsetInitSlot), bytes32(0), "no state should live at a non-ERC-7201 slot"
        );
    }

    /// @notice Pins the `addKey` keyType write — `k.keyType = _type` MUST store the passed-in
    ///         type, not a hardcoded constant. The default `OnchainIDSetup` only uses ECDSA
    ///         keys (which is `1`), so an accidental hardcoding to `1` would be invisible to
    ///         every existing test. This one passes RSA (`2`) and asserts readback.
    function test_addKey_storesRequestedKeyType() public {
        bytes32 freshKey = keccak256("fresh-rsa-key-for-write-path-pin");
        vm.prank(alice);
        aliceIdentity.addKey(freshKey, KeyPurposes.ACTION, KeyTypes.RSA);
        (, uint256 keyType,) = aliceIdentity.getKey(freshKey);
        assertEq(keyType, KeyTypes.RSA, "stored keyType must match the requested type");
    }

    /// @notice Pins the `signerData` assignment in `_setupInitialManagementKey`. The initial
    ///         MANAGEMENT key's `signerData` MUST be the packed bytes of the bootstrap address.
    ///
    ///         Tests using the *factory-created* `aliceIdentity` cannot exercise this path
    ///         because the factory's bootstrap key is REMOVED at the end of
    ///         `IdFactory._setupIdentity`, and alice's key (the surviving one) is added
    ///         separately via `addKeyWithData` — bypassing `_setupInitialManagementKey` entirely.
    ///
    ///         This test deploys Identity DIRECTLY, so the constructor's
    ///         `_setupInitialManagementKey(alice)` is the only writer of alice's `signerData`.
    function test_initialManagementKey_signerData_matchesBootstrapAddress() public {
        Identity directIdentity = new Identity(alice, false);
        (bytes memory storedSigner,) = directIdentity.getKeyData(aliceKeyHash);
        assertEq(
            storedSigner, abi.encodePacked(alice), "initial MANAGEMENT signerData MUST be the bootstrap address bytes"
        );
    }

    /// @notice Pins the scope of the last-MANAGEMENT protection in `_removeKeyPurpose`. The
    ///         `if (_purpose == KeyPurposes.MANAGEMENT) { require(length > 1, ...) }` branch
    ///         MUST gate the MANAGEMENT-purpose case only. If it ever ran on every `removeKey`
    ///         — including non-MANAGEMENT purposes — it would falsely block legitimate
    ///         removals whenever exactly one MANAGEMENT key remained.
    ///
    ///         We first reduce aliceIdentity to a single MANAGEMENT key (alice), then remove
    ///         a non-MANAGEMENT purpose (carol's CLAIM_SIGNER). The removal must succeed.
    function test_removeNonMgmtPurpose_singleMgmtRemaining_succeeds() public {
        bytes32 kamHash = keccak256(abi.encodePacked(address(onchainidSetup.keyApprovalModule)));
        bytes32 carolHash = ClaimSignerHelper.addressToKey(carol);

        // Drop the KAM module's MANAGEMENT purpose so alice is the sole MANAGEMENT key.
        // (KAM held MANAGEMENT via IdentityHelper.legacyQueueModules.) This first remove
        // exercises the MANAGEMENT branch with length()==2 and is just setup for the
        // discriminating second remove below.
        vm.prank(alice);
        aliceIdentity.removeKey(kamHash, KeyPurposes.MANAGEMENT);
        assertEq(
            aliceIdentity.getKeysByPurpose(KeyPurposes.MANAGEMENT).length,
            1,
            "alice should be sole MANAGEMENT key after KAM purpose removed"
        );

        // Now the discriminating call: remove a non-MANAGEMENT purpose. The
        // `_purpose == MANAGEMENT` branch must stay skipped (purpose is CLAIM_SIGNER), so the
        // last-MANAGEMENT length check never runs. If it ever did, the length==1 condition
        // would falsely revert `CannotRemoveLastManagementKey`.
        vm.prank(alice);
        aliceIdentity.removeKey(carolHash, KeyPurposes.CLAIM_SIGNER);

        assertFalse(
            aliceIdentity.keyHasPurpose(carolHash, KeyPurposes.CLAIM_SIGNER),
            "carol's CLAIM_SIGNER purpose should be removed"
        );
    }

}
