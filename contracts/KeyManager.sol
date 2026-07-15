// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { Errors } from "./libraries/Errors.sol";
import { hashAddress } from "./libraries/Hashing.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";

/// @notice Minimal view of the enshrined ERC-734 registry module (the merged {ERC734Validator}).
///         The account no longer stores keys locally; it delegates the key registry to this
///         module. Reads used by the account's own auth gates go through {keyHasPurpose}; writes
///         forward to {addKey} / {removeKey}; {getKeyData} / {getKeyPurposes} back the account's
///         write forwarders and module-purpose cleanup.
interface IKeyRegistryModule {

    function keyHasPurpose(address account, bytes32 keyHash, uint256 purpose) external view returns (bool);

    function getKeyData(address account, bytes32 keyHash) external view returns (bytes memory, bytes memory);

    function getKeyPurposes(address account, bytes32 keyHash) external view returns (uint256[] memory);

    function addKey(bytes calldata signerData, bytes calldata clientData, uint256 purpose, uint256 keyType) external;

    function removeKey(bytes32 keyHash, uint256 purpose) external;

}

/**
 * @title KeyManager
 * @notice Thin ERC-734 bootstrap facade for an identity. It keeps the `onlyManager` /
 *         `delegatedOnly` gates and the ERC-734 write entry points, but no longer owns any
 *         local key storage.
 *
 * @dev The canonical key registry lives in the enshrined {ERC734Validator} module. This contract:
 *      - reads MANAGEMENT membership for {onlyManager} via a staticcall to the enshrined module;
 *      - forwards ERC-734 key writes (`addKey`, `addKeyWithData`, `removeKey`) to the module as
 *        self-calls;
 *      - keeps its ERC-7201 storage slot only for the `initialized` / `canInteract` flags and the
 *        enshrined `registryModule` address.
 *
 *      The ERC-734 *getter* selectors (`getKey`, `getKeyPurposes`, `getKeysByPurpose`,
 *      `keyHasPurpose`) are served by the account's ERC-7579 fallback, which routes them to the
 *      enshrined module. They are intentionally not implemented here.
 *
 * @custom:security This contract uses ERC-7201 storage slots to prevent storage collision
 *                  attacks in upgradeable contracts.
 */
contract KeyManager {

    /**
     * @dev Storage struct for the key-manager bootstrap facade.
     * @custom:storage-location erc7201:onchainid.keymanager.storage
     */
    struct KeyStorage {
        /// @dev Flag indicating if the contract has been initialized
        bool initialized;
        /// @dev Flag preventing direct calls to the library implementation
        bool canInteract;
        /// @dev The enshrined ERC-734 registry module (the merged {ERC734Validator}). Set once,
        ///      during {Identity.initialize}, and read by every `onlyManager`-gated call and by
        ///      the ERC-734 write forwarders.
        address registryModule;
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
    /// @dev MANAGEMENT membership is read from the enshrined registry module rather than from local
    ///      storage. The self-call branch (`msg.sender == address(this)`) covers post-execution
    ///      dispatch from the queue module or the EntryPoint, and the init path before any key exists.
    modifier onlyManager() {
        require(
            msg.sender == address(this) || _moduleKeyHasPurpose(hashAddress(msg.sender), KeyPurposes.MANAGEMENT),
            Errors.SenderDoesNotHaveManagementKey()
        );
        _;
    }

    /// @notice Add a key to the identity. Caller must hold MANAGEMENT, or be the identity itself.
    /// @dev The 3-arg {addKey} carries no signer bytes; it looks up the signer bytes stored in the
    ///      module for `_key` and forwards. Reverts if the key is unknown to the module.
    function addKey(bytes32 _key, uint256 _purpose, uint256 _type)
        public
        virtual
        delegatedOnly
        onlyManager
        returns (bool success)
    {
        _addKey(_key, _purpose, _type);
        return true;
    }

    /// @dev Internal version of {addKey}. No modifiers. Used by the external entry point and by
    ///      the initialization path. Looks up the module-stored signer bytes for `_key` (the module
    ///      derives the keyHash from the signer bytes), then forwards the write.
    function _addKey(bytes32 _key, uint256 _purpose, uint256 _type) internal {
        (bytes memory signerData, bytes memory clientData) =
            IKeyRegistryModule(_registryModule()).getKeyData(address(this), _key);
        require(signerData.length != 0, Errors.InvalidSignerData());
        IKeyRegistryModule(_registryModule()).addKey(signerData, clientData, _purpose, _type);
    }

    /// @notice Remove a purpose from a key. Caller must hold MANAGEMENT, or be the identity itself.
    /// @dev The module enforces the "can't remove the last MANAGEMENT key" guard.
    function removeKey(bytes32 _key, uint256 _purpose) public virtual delegatedOnly onlyManager returns (bool success) {
        _removeKeyPurpose(_key, _purpose);
        return true;
    }

    /// @dev Shared remove logic. The public {removeKey} uses it, and so does
    ///      {SmartAccount._uninstallModule} when it strips purposes off an uninstalled module.
    ///      Forwards to the module, which keeps the "can't remove the last MANAGEMENT key" check.
    function _removeKeyPurpose(bytes32 _key, uint256 _purpose) internal {
        IKeyRegistryModule(_registryModule()).removeKey(_key, _purpose);
    }

    /**
     * @notice Register a key alongside its ERC-7913 signer bytes and client metadata.
     * @dev Convenience entry point used by the factory and tests to set up a signer in one shot.
     *      Forwards to the enshrined module, which derives the keyHash from `_signerData`.
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

    /// @dev Internal version of {addKeyWithData}. No modifiers. Used by the external entry point and
    ///      by the initialization path. The keyHash MUST commit to the signer bytes; the module
    ///      re-derives it, so a mismatch is rejected here before forwarding.
    function _addKeyWithData(
        bytes32 _key,
        uint256 _purpose,
        uint256 _type,
        bytes memory _signerData,
        bytes memory _clientData
    ) internal {
        // The keyHash MUST commit to the signer bytes forwarded with it. Without this guard a caller
        // could register one keyHash while attaching a different signer's bytes.
        require(_key == keccak256(_signerData), Errors.InvalidSignerData());
        IKeyRegistryModule(_registryModule()).addKey(_signerData, _clientData, _purpose, _type);
    }

    /// @dev The enshrined registry module. Reverts through the caller if never set.
    function _registryModule() internal view returns (address) {
        return _getKeyStorage().registryModule;
    }

    /// @dev Set-once enshrine of the registry module. Called from {Identity.initialize} once the
    ///      validator that holds the registry has been installed (its `onInstall` seeded the first
    ///      MANAGEMENT key). Reverts if already set, or if `module` is the zero address.
    function _enshrineRegistryModule(address module) internal {
        KeyStorage storage ks = _getKeyStorage();
        require(module != address(0), Errors.ZeroAddress());
        require(ks.registryModule == address(0), Errors.IdentityNoValidatorOrExecutor());
        ks.registryModule = module;
    }

    /// @dev MANAGEMENT / purpose read for the account itself, backed by the enshrined module.
    function _moduleKeyHasPurpose(bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        return IKeyRegistryModule(_registryModule()).keyHasPurpose(address(this), keyHash, purpose);
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
