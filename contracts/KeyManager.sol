// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC734 } from "./interface/IERC734.sol";
import { Errors } from "./libraries/Errors.sol";
import { hashAddress } from "./libraries/Hashing.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";
import { KeyTypes } from "./libraries/KeyTypes.sol";
import { Structs } from "./storage/Structs.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title KeyManager
 * @notice Key registry for ERC-734 identities.
 *
 * @dev Owns the canonical key state — `keys`, `keysByPurpose`, `keyHasPurpose` — and is the
 *      single source of truth that ERC-734 callers, the {KeyApprovalModule}, and {SmartAccount}'s
 *      native validator all read from.
 *
 *      Execute/approve queue logic has been *externalized* to {KeyApprovalModule} (an ERC-7579
 *      fallback handler + executor module). This contract no longer owns:
 *      - the `executionNonce`,
 *      - the `executions[]` queue,
 *      - the auto-approval rule table.
 *
 *      The `execute` and `approve` selectors on {IERC734} are still resolved by Identity
 *      instances — the account's ERC-7579 fallback forwards them to the installed
 *      {KeyApprovalModule}. Calls placed when no queue module is installed revert via the
 *      `ERC7579MissingFallbackHandler` path inherited from OZ's `AccountERC7579Upgradeable`.
 *
 * @custom:security This contract uses ERC-7201 storage slots to prevent storage collision
 *                  attacks in upgradeable contracts.
 */
contract KeyManager is IERC734 {

    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @dev Storage struct for the key registry.
     * @custom:storage-location erc7201:onchainid.keymanager.storage
     */
    struct KeyStorage {
        /// @dev Mapping of key hash to Key struct as defined by IERC734
        mapping(bytes32 => Structs.Key) keys;
        /// @dev Mapping of purpose to set of key hashes (EnumerableSet for O(1) add/remove)
        mapping(uint256 => EnumerableSet.Bytes32Set) keysByPurpose;
        /// @dev Flag indicating if the contract has been initialized
        bool initialized;
        /// @dev Flag preventing direct calls to the library implementation
        bool canInteract;
    }

    /// @dev ERC-7201 storage slot. Kept identical to the pre-refactor slot to avoid
    ///      reshuffling storage on existing deployments.
    bytes32 internal constant _KEY_STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256(bytes("onchainid.keymanager.storage"))) - 1)
    ) & ~bytes32(uint256(0xff));

    /// @notice Prevents any direct call to the implementation contract (marked
    ///         by `canInteract == false`).
    modifier delegatedOnly() {
        _checkDelegated();
        _;
    }

    /// @notice Requires a MANAGEMENT key, or an internal self-call (`msg.sender == address(this)`).
    modifier onlyManager() {
        require(
            msg.sender == address(this) || keyHasPurpose(hashAddress(msg.sender), KeyPurposes.MANAGEMENT),
            Errors.SenderDoesNotHaveManagementKey()
        );
        _;
    }

    /// @inheritdoc IERC734
    function getKey(bytes32 _key)
        external
        view
        virtual
        override
        returns (uint256[] memory purposes, uint256 keyType, bytes32 key)
    {
        KeyStorage storage ks = _getKeyStorage();
        return (ks.keys[_key].purposes.values(), ks.keys[_key].keyType, ks.keys[_key].key);
    }

    /// @inheritdoc IERC734
    function getKeyPurposes(bytes32 _key) external view virtual override returns (uint256[] memory _purposes) {
        return _getKeyStorage().keys[_key].purposes.values();
    }

    /// @inheritdoc IERC734
    function getKeysByPurpose(uint256 _purpose) external view virtual override returns (bytes32[] memory keys) {
        return _getKeyStorage().keysByPurpose[_purpose].values();
    }

    /// @notice Returns the (signerData, clientData) tuple for a key. The signerData encoding is
    ///         consumed by application-level verification paths (e.g. `isClaimValid`).
    function getKeyData(bytes32 _keyHash)
        external
        view
        virtual
        returns (bytes memory signerData, bytes memory clientData)
    {
        KeyStorage storage ks = _getKeyStorage();
        return (ks.keys[_keyHash].signerData, ks.keys[_keyHash].clientData);
    }

    /// @inheritdoc IERC734
    /// @dev O(1) via EnumerableSet's `contains`.
    function keyHasPurpose(bytes32 _key, uint256 _purpose) public view virtual override returns (bool) {
        KeyStorage storage ks = _getKeyStorage();
        if (ks.keys[_key].key == 0) return false;
        return ks.keys[_key].purposes.contains(_purpose) || ks.keys[_key].purposes.contains(KeyPurposes.MANAGEMENT);
    }

    /// @inheritdoc IERC734
    /// @dev Caller must hold MANAGEMENT, or be the identity itself (post-execution from
    ///      the queue module or the EntryPoint).
    function addKey(bytes32 _key, uint256 _purpose, uint256 _type)
        public
        virtual
        override
        delegatedOnly
        onlyManager
        returns (bool success)
    {
        KeyStorage storage ks = _getKeyStorage();
        Structs.Key storage k = ks.keys[_key];

        if (k.key == bytes32(0)) {
            k.key = _key;
            k.keyType = _type;
        } else {
            // The stored type wins on re-purpose. Reject a mismatched `_type` so the emitted
            // `KeyAdded` event can't surface a type that storage doesn't actually hold.
            require(k.keyType == _type, Errors.KeyTypeMismatch(_key, k.keyType, _type));
        }

        require(k.purposes.add(_purpose), Errors.KeyAlreadyHasPurpose(_key, _purpose));
        ks.keysByPurpose[_purpose].add(_key);

        emit KeyAdded(_key, _purpose, _type);
        return true;
    }

    /// @inheritdoc IERC734
    /// @dev Deletes the key entry when no purposes remain. The last MANAGEMENT key cannot
    ///      be removed; doing so would leave the identity unrecoverable.
    function removeKey(bytes32 _key, uint256 _purpose)
        public
        virtual
        override
        delegatedOnly
        onlyManager
        returns (bool success)
    {
        return _removeKeyPurpose(_key, _purpose);
    }

    /// Shared remove logic. The public {removeKey} uses it, and so does
    /// {SmartAccount._uninstallModule} when it strips purposes off an uninstalled
    /// module. We keep the "can't remove the last MANAGEMENT key" check in here so
    /// both paths get it for free. Callers are responsible for their own access checks.
    function _removeKeyPurpose(bytes32 _key, uint256 _purpose) internal returns (bool success) {
        KeyStorage storage ks = _getKeyStorage();
        Structs.Key storage k = ks.keys[_key];

        require(k.key == _key, Errors.KeyNotRegistered(_key));

        if (_purpose == KeyPurposes.MANAGEMENT) {
            // Removing the last MANAGEMENT key would leave the identity unrecoverable.
            require(ks.keysByPurpose[KeyPurposes.MANAGEMENT].length() > 1, Errors.CannotRemoveLastManagementKey());
        }

        require(k.purposes.remove(_purpose), Errors.KeyDoesNotHavePurpose(_key, _purpose));
        ks.keysByPurpose[_purpose].remove(_key);

        emit KeyRemoved(_key, _purpose, k.keyType);

        if (k.purposes.length() == 0) {
            delete ks.keys[_key];
        }

        return true;
    }

    /**
     * @notice Register a key alongside its ERC-7913 signer bytes and client metadata.
     * @dev Convenience entry point used by the factory and tests to set up a signer in one shot.
     */
    function addKeyWithData(
        bytes32 _key,
        uint256 _purpose,
        uint256 _type,
        bytes memory _signerData,
        bytes memory _clientData
    ) external virtual delegatedOnly onlyManager {
        _addKeyWithData(_key, _purpose, _type, _signerData, _clientData);
    }

    /// @dev Internal version of {addKeyWithData}. No modifiers. Used by both the external
    ///      entry point and by initialization paths that run before any MANAGEMENT key exists.
    function _addKeyWithData(
        bytes32 _key,
        uint256 _purpose,
        uint256 _type,
        bytes memory _signerData,
        bytes memory _clientData
    ) internal {
        // The keyHash MUST commit to the signer bytes stored alongside it. Without this guard a
        // caller could register one keyHash while attaching a different signer's bytes, which
        // would silently corrupt any downstream lookup of `signerData`.
        require(_key == keccak256(_signerData), Errors.InvalidSignerData());

        // Inline the addKey storage writes so we don't go through the modifier-gated public
        // addKey from the init path.
        KeyStorage storage ks = _getKeyStorage();
        Structs.Key storage k = ks.keys[_key];

        if (k.key == bytes32(0)) {
            k.key = _key;
            k.keyType = _type;
        } else {
            require(k.keyType == _type, Errors.KeyTypeMismatch(_key, k.keyType, _type));
        }

        require(k.purposes.add(_purpose), Errors.KeyAlreadyHasPurpose(_key, _purpose));
        ks.keysByPurpose[_purpose].add(_key);

        ks.keys[_key].signerData = _signerData;
        ks.keys[_key].clientData = _clientData;

        emit KeyAdded(_key, _purpose, _type);
    }

    function _checkDelegated() internal view {
        require(_getKeyStorage().canInteract, Errors.InteractingWithLibraryContractForbidden());
    }

    function _getKeyStorage() internal pure returns (KeyStorage storage s) {
        bytes32 slot = _KEY_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

}
