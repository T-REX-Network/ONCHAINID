// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.28;

import { Errors } from "./libraries/Errors.sol";
import { Events } from "./libraries/Events.sol";
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
 *      The module address comes from {registryModule}, implemented by the concrete account
 *      ({Identity}) as an immutable fixed at implementation deploy time.
 *
 *      The ERC-734 *getter* selectors (`getKey`, `getKeyPurposes`, `getKeysByPurpose`,
 *      `keyHasPurpose`) are implemented here as plain functions forwarding to the enshrined
 *      module, so key-state reads through the account are always answered by the registry and
 *      never by an installed fallback handler. A real function takes precedence over ERC-7579
 *      fallback dispatch, so these selectors cannot be routed elsewhere by module installation.
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
        emit Events.CalledBy(msg.sender, msg.sig);
        _addKey(_key, _purpose, _type);
        return true;
    }

    /// @dev Internal version of {addKey}. No modifiers. Used by the external entry point and by
    ///      the initialization path. Looks up the module-stored signer bytes for `_key` (the module
    ///      derives the keyHash from the signer bytes), then forwards the write.
    function _addKey(bytes32 _key, uint256 _purpose, uint256 _type) internal {
        (bytes memory signerData, bytes memory clientData) =
            ERC734Validator(registryModule()).getKeyData(address(this), _key);
        require(signerData.length != 0, Errors.InvalidSignerData());
        ERC734Validator(registryModule()).addKey(signerData, clientData, _purpose, _type);
    }

    /// @notice Remove a purpose from a key. Caller must hold MANAGEMENT, or be the identity itself.
    /// @dev The module enforces the "can't remove the last MANAGEMENT key" guard.
    function removeKey(bytes32 _key, uint256 _purpose) public virtual onlyManagerOrSelf returns (bool success) {
        emit Events.CalledBy(msg.sender, msg.sig);
        _removeKeyPurpose(_key, _purpose);
        return true;
    }

    /// @dev Shared remove logic. The public {removeKey} uses it, and so does
    ///      {SmartAccount._uninstallModule} when it strips purposes off an uninstalled module.
    ///      Forwards to the module, which keeps the "can't remove the last MANAGEMENT key" check.
    function _removeKeyPurpose(bytes32 _key, uint256 _purpose) internal {
        ERC734Validator(registryModule()).removeKey(_key, _purpose);
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
        emit Events.CalledBy(msg.sender, msg.sig);
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
        ERC734Validator(registryModule()).addKey(_signerData, _clientData, _purpose, _type);
    }

    /// @notice `IERC734.getKey` for this identity, answered by the enshrined registry.
    function getKey(bytes32 _key)
        public
        view
        virtual
        returns (uint256[] memory purposes, uint256 keyType, bytes32 key)
    {
        return ERC734Validator(registryModule()).getKey(address(this), _key);
    }

    /// @notice `IERC734.getKeyPurposes` for this identity. Returns the full set; use the
    ///         `(_key, start, end)` overload for large sets.
    function getKeyPurposes(bytes32 _key) public view virtual returns (uint256[] memory purposes) {
        return ERC734Validator(registryModule()).getKeyPurposes(address(this), _key);
    }

    /// @notice Paginated variant of {getKeyPurposes}. Returns purposes in the index range
    ///         `[start, end)`; `end` past the set size returns the available tail.
    function getKeyPurposes(bytes32 _key, uint256 start, uint256 end)
        public
        view
        virtual
        returns (uint256[] memory purposes)
    {
        return ERC734Validator(registryModule()).getKeyPurposes(address(this), _key, start, end);
    }

    /// @notice `IERC734.getKeysByPurpose` for this identity. Returns the full set; use the
    ///         `(_purpose, start, end)` overload for large sets.
    function getKeysByPurpose(uint256 _purpose) public view virtual returns (bytes32[] memory keys) {
        return ERC734Validator(registryModule()).getKeysByPurpose(address(this), _purpose);
    }

    /// @notice Paginated variant of {getKeysByPurpose}. Returns key hashes in the index range
    ///         `[start, end)`; `end` past the set size returns the available tail.
    function getKeysByPurpose(uint256 _purpose, uint256 start, uint256 end)
        public
        view
        virtual
        returns (bytes32[] memory keys)
    {
        return ERC734Validator(registryModule()).getKeysByPurpose(address(this), _purpose, start, end);
    }

    /// @notice `IERC734.keyHasPurpose` for this identity. MANAGEMENT satisfies any purpose.
    function keyHasPurpose(bytes32 _key, uint256 _purpose) public view virtual returns (bool exists) {
        return _moduleKeyHasPurpose(_key, _purpose);
    }

    /// @notice The enshrined registry module. Implemented by the concrete account ({Identity}) as
    ///         an immutable, so reading it costs no storage access.
    function registryModule() public view virtual returns (address);

    /// @dev MANAGEMENT / purpose read for the account itself, backed by the enshrined module.
    function _moduleKeyHasPurpose(bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        return ERC734Validator(registryModule()).keyHasPurpose(address(this), keyHash, purpose);
    }

}
