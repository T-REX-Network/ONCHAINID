// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { Events } from "contracts/libraries/Events.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Vm } from "forge-std/Vm.sol";

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
        (uint256[] memory purposes, uint256 keyType, bytes32 key) = IERC734(address(aliceIdentity)).getKey(aliceKeyHash);

        assertEq(key, aliceKeyHash);
        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_RetrieveExistingKeyPurposes() public view {
        uint256[] memory purposes = IERC734(address(aliceIdentity)).getKeyPurposes(aliceKeyHash);

        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
    }

    function test_RetrieveExistingKeysWithGivenPurpose() public view {
        bytes32[] memory keys = IERC734(address(aliceIdentity)).getKeysByPurpose(KeyPurposes.MANAGEMENT);

        // Alice is a MANAGEMENT key. The KeyApprovalModule also holds MANAGEMENT but as a
        // MODULE key it cannot sign, so it is left out of this enumeration.
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
        bool hasPurpose = IERC734(address(aliceIdentity)).keyHasPurpose(aliceKeyHash, KeyPurposes.MANAGEMENT);

        assertTrue(hasPurpose);
    }

    function test_ReturnTrueIfKeyIsManagementKeyButNotGivenPurpose() public view {
        // MANAGEMENT keys have universal permissions, so they return true for any purpose
        bool hasPurpose = IERC734(address(aliceIdentity)).keyHasPurpose(aliceKeyHash, KeyPurposes.ACTION);

        assertTrue(hasPurpose);
    }

    function test_ReturnFalseIfKeyDoesNotHaveGivenPurpose() public view {
        bool hasPurpose = IERC734(address(aliceIdentity)).keyHasPurpose(bobKeyHash, KeyPurposes.ACTION);

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

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = IERC734(address(aliceIdentity)).getKey(aliceKeyHash);

        assertEq(key, aliceKeyHash);
        assertEq(purposes.length, 2);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(purposes[1], KeyPurposes.ACTION);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_AddNewKeyWithPurpose() public {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA, abi.encodePacked(bob), "");

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = IERC734(address(aliceIdentity)).getKey(bobKeyHash);

        assertEq(key, bobKeyHash);
        assertEq(purposes.length, 1);
        assertEq(purposes[0], KeyPurposes.MANAGEMENT);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_RevertAddKey_WhenKeyAlreadyHasPurpose() public {
        // The registry module rejects re-adding a purpose the key already holds with
        // KeyAlreadyRegistered(keyHash) (the EnumerableSet.add returned false).
        vm.expectRevert(abi.encodeWithSelector(ERC734Validator.KeyAlreadyRegistered.selector, aliceKeyHash));
        vm.prank(alice);
        aliceIdentity.addKey(aliceKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA);
    }

    /// @notice Re-purposing an existing key with a different `_type` is rejected.
    function test_RevertAddKey_WhenKeyTypeDoesNotMatchExisting() public {
        // aliceKeyHash already exists with keyType = ECDSA. Attempt to add a new purpose with RSA.
        // The registry module signals the mismatch with KeyTypeMismatch(keyHash).
        vm.expectRevert(abi.encodeWithSelector(ERC734Validator.KeyTypeMismatch.selector, aliceKeyHash));
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
        aliceIdentity.addKeyWithData(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA, abi.encodePacked(bob), "");

        vm.prank(alice);
        aliceIdentity.removeKey(aliceKeyHash, KeyPurposes.MANAGEMENT);

        (uint256[] memory purposes, uint256 keyType, bytes32 key) = IERC734(address(aliceIdentity)).getKey(aliceKeyHash);

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
        // Add bob as MANAGEMENT + ACTION key. The first call registers the new key (data-carrying
        // form); the second only adds a purpose to the now-existing key (3-arg form).
        vm.startPrank(alice);
        aliceIdentity.addKeyWithData(bobKeyHash, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA, abi.encodePacked(bob), "");
        aliceIdentity.addKey(bobKeyHash, KeyPurposes.ACTION, KeyTypes.ECDSA);

        // Remove MANAGEMENT purpose
        aliceIdentity.removeKey(bobKeyHash, KeyPurposes.MANAGEMENT);
        vm.stopPrank();

        // Verify the key still has ACTION purpose only
        (uint256[] memory purposes, uint256 keyType, bytes32 key) = IERC734(address(aliceIdentity)).getKey(bobKeyHash);

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
        assertFalse(IERC734(address(aliceIdentity)).keyHasPurpose(carolKeyHash, KeyPurposes.CLAIM_SIGNER));
    }

    /// @notice Remove a key's only purpose — key should be fully deleted
    function test_RemoveKeyWithSinglePurpose() public {
        // david has ACTION only on aliceIdentity (added in setUp)
        bytes32 davidKeyHash = ClaimSignerHelper.addressToKey(david);

        // david has exactly one purpose (ACTION)
        uint256[] memory purposes = IERC734(address(aliceIdentity)).getKeyPurposes(davidKeyHash);
        assertEq(purposes.length, 1, "David should have exactly 1 purpose");

        // Remove ACTION purpose
        vm.prank(alice);
        aliceIdentity.removeKey(davidKeyHash, KeyPurposes.ACTION);

        // Key should be fully deleted
        (, uint256 keyType2, bytes32 key2) = IERC734(address(aliceIdentity)).getKey(davidKeyHash);
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
        vm.expectEmit(address(aliceIdentity));
        emit Events.CalledBy(alice, aliceIdentity.addKeyWithData.selector);
        vm.expectEmit(address(onchainidSetup.signatureValidator));
        emit ERC734Validator.KeyDataSet(address(aliceIdentity), keyHash, signerData, "");
        vm.expectEmit(address(onchainidSetup.signatureValidator));
        emit ERC734Validator.KeyAdded(address(aliceIdentity), keyHash, KeyPurposes.ACTION, KeyTypes.ECDSA);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.ACTION, KeyTypes.ECDSA, signerData, "");

        (, uint256 keyType, bytes32 storedKey) = IERC734(address(aliceIdentity)).getKey(keyHash);
        assertEq(storedKey, keyHash);
        assertEq(keyType, KeyTypes.ECDSA);
    }

    function test_AddKeyWithData_repurposeDoesNotReemitKeyDataSet() public {
        bytes32 keyHash = keccak256(abi.encodePacked(bob));
        bytes memory signerData = abi.encodePacked(bob);
        vm.prank(alice);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.ACTION, KeyTypes.ECDSA, signerData, "");

        vm.recordLogs();
        vm.prank(alice);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA, signerData, "");
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 dataSetTopic = keccak256("KeyDataSet(address,bytes32,bytes,bytes)");
        bytes32 addedTopic = keccak256("KeyAdded(address,bytes32,uint256,uint256)");
        bool addedSeen;
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(logs[i].topics[0] != dataSetTopic, "KeyDataSet must not fire on re-purpose");
            if (logs[i].topics[0] == addedTopic) addedSeen = true;
        }
        assertTrue(addedSeen, "KeyAdded still fires for the new purpose");
    }

    // ============ Dynamic field caps ============

    function test_RevertAddKey_WhenSignerDataExceedsCap() public {
        bytes memory signerData = new bytes(Structs.MAX_SIGNER_DATA_LENGTH + 1);

        vm.prank(alice);
        vm.expectRevert(ERC734Validator.InvalidSignerLength.selector);
        aliceIdentity.addKeyWithData(keccak256(signerData), KeyPurposes.ACTION, KeyTypes.RSA, signerData, "");
    }

    function test_RevertAddKey_WhenClientDataExceedsCap() public {
        bytes memory signerData = abi.encodePacked(bob);
        bytes memory clientData = new bytes(Structs.MAX_CLIENT_DATA_LENGTH + 1);

        vm.prank(alice);
        vm.expectRevert(Errors.ClientDataTooLong.selector);
        aliceIdentity.addKeyWithData(keccak256(signerData), KeyPurposes.ACTION, KeyTypes.ECDSA, signerData, clientData);
    }

    function test_AddKey_AcceptsFieldsAtCap() public {
        bytes memory signerData = new bytes(Structs.MAX_SIGNER_DATA_LENGTH);
        signerData[0] = 0x01;
        bytes memory clientData = new bytes(Structs.MAX_CLIENT_DATA_LENGTH);
        bytes32 keyHash = keccak256(signerData);

        vm.prank(alice);
        aliceIdentity.addKeyWithData(keyHash, KeyPurposes.ACTION, KeyTypes.RSA, signerData, clientData);

        assertTrue(IERC734(address(aliceIdentity)).keyHasPurpose(keyHash, KeyPurposes.ACTION));
    }

}
