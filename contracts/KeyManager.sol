// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { Errors } from "./libraries/Errors.sol";
import { hashAddress } from "./libraries/Hashing.sol";
import { KeyPurposes } from "./libraries/KeyPurposes.sol";
import { ERC734Validator } from "./modules/validators/ERC734Validator.sol";

/**
 * @title KeyManager
 * @notice Thin ERC-734 bootstrap facade for an identity. It keeps the `onlyManagerOrSelf` gate and
 *         the ERC-734 write entry points, but owns no storage at all.
 *
 * @dev The canonical key registry lives in the enshrined {ERC734Validator} module. This contract:
 *      - reads MANAGEMENT membership for {onlyManagerOrSelf} via a staticcall to the enshrined module;
 *      - forwards ERC-734 key writes (`addKey`, `addKeyWithData`, `removeKey`) to the module as
 *        self-calls.
 *
 *      The module address comes from {_registryModule}, implemented by the concrete account
 *      ({Identity}) as an immutable fixed at implementation deploy time.
 *
 *      The ERC-734 *getter* selectors (`getKey`, `getKeyPurposes`, `getKeysByPurpose`,
 *      `keyHasPurpose`) are served by the account's ERC-7579 fallback, which routes them to the
 *      enshrined module. They are intentionally not implemented here.
 */
abstract contract KeyManager {

    /// @notice Requires a MANAGEMENT key, or an internal self-call (`msg.sender == address(this)`).
    modifier onlyManagerOrSelf() {
        _checkManagerOrSelf();
        _;
    }

    /// @dev MANAGEMENT membership is read from the registry module rather than from local storage.
    ///      The self-call branch (`msg.sender == address(this)`) covers post-execution dispatch from
    ///      the queue module or the EntryPoint, and the init path before any key exists.
    function _checkManagerOrSelf() internal view {
        require(
            msg.sender == address(this) || _moduleKeyHasPurpose(hashAddress(msg.sender), KeyPurposes.MANAGEMENT),
            Errors.SenderDoesNotHaveManagementKey()
        );
    }

    /// @notice Add a key to the identity. Caller must hold MANAGEMENT, or be the identity itself.
    /// @dev The 3-arg {addKey} carries no signer bytes; it looks up the signer bytes stored in the
    ///      module for `_key` and forwards. Reverts if the key is unknown to the module.
    function addKey(bytes32 _key, uint256 _purpose, uint256 _type)
        public
        virtual
        onlyManagerOrSelf
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
            ERC734Validator(_registryModule()).getKeyData(address(this), _key);
        require(signerData.length != 0, Errors.InvalidSignerData());
        ERC734Validator(_registryModule()).addKey(signerData, clientData, _purpose, _type);
    }

    /// @notice Remove a purpose from a key. Caller must hold MANAGEMENT, or be the identity itself.
    /// @dev The module enforces the "can't remove the last MANAGEMENT key" guard.
    function removeKey(bytes32 _key, uint256 _purpose) public virtual onlyManagerOrSelf returns (bool success) {
        _removeKeyPurpose(_key, _purpose);
        return true;
    }

    /// @dev Shared remove logic. The public {removeKey} uses it, and so does
    ///      {SmartAccount._uninstallModule} when it strips purposes off an uninstalled module.
    ///      Forwards to the module, which keeps the "can't remove the last MANAGEMENT key" check.
    function _removeKeyPurpose(bytes32 _key, uint256 _purpose) internal {
        ERC734Validator(_registryModule()).removeKey(_key, _purpose);
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
    ) external virtual onlyManagerOrSelf {
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
        ERC734Validator(_registryModule()).addKey(_signerData, _clientData, _purpose, _type);
    }

    /// @dev The enshrined registry module. Implemented by the concrete account ({Identity}) as an
    ///      immutable, so reading it costs no storage access.
    function _registryModule() internal view virtual returns (address);

    /// @dev MANAGEMENT / purpose read for the account itself, backed by the enshrined module.
    function _moduleKeyHasPurpose(bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        return ERC734Validator(_registryModule()).keyHasPurpose(address(this), keyHash, purpose);
    }

}
