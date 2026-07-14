// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { Execution, IERC7579Execution } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { IERC734 } from "../../interface/IERC734.sol";
import { IERC735 } from "../../interface/IERC735.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";
import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC734Validator
/// @notice Holds the authorization side of the ERC-734 registry (keys + MANAGEMENT / ACTION /
///         PROPOSER purposes) and per-target scoping inside the validator, so the account only
///         routes to the validator and never decodes the signature.
///
///         Dual registry: authorization purposes (MANAGEMENT / ACTION / PROPOSER) live here;
///         identity purposes (CLAIM_SIGNER / CLAIM_ADDER / ENCRYPTION) stay on the account's
///         KeyManager, because ERC-735 claim verification reads `keyHasPurpose` on the identity
///         account (see `ClaimsModule._getClaimStatus`). The claim branches of the scoping rule
///         therefore query the account, not this registry.
///
///         The account calls `validateUserOp`; this module verifies the signature, checks the
///         signer is a registered key, and enforces the purpose the userOp needs.
///
///         Constraint: the scoping rule guards this validator's own address, but it does not
///         know about other privileged targets (installed executors, fallback handlers). A
///         userOp from an ACTION signer that calls `execute(installedExecutor, ...)` reads as an
///         external target here, so ACTION suffices; the call then reaches the executor with
///         `msg.sender == account`. Executor and fallback modules must gate their own callers
///         rather than trust that reaching them implies authorization.
///
/// @dev userOp signature wire format: `abi.encode(bytes signer, bytes signature)`, where
///      `signer` is ERC-7913 (20 bytes = EOA/1271, longer = `verifier(20) || key`). Storage is
///      ERC-7201 namespaced.
contract ERC734Validator is ERC7579Validator {

    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev Same shape as `Structs.Key`. `signerData` is the ERC-7913 verification material
    ///      (for WebAuthn, `verifier(20) || pubkey`), committed by `keyHash == keccak256(signerData)`.
    ///      `clientData` is non-cryptographic metadata (e.g. WebAuthn credentialId) kept per key.
    ///      `keyType` is ECDSA / RSA / WEBAUTHN / MODULE.
    struct Key {
        EnumerableSet.UintSet purposes;
        uint256 keyType;
        bytes signerData;
        bytes clientData;
    }

    /// @dev ERC-734 key registry, scoped to one account. `allKeys` tracks every registered
    ///      keyHash so `_clearRegistry` can delete each `Key` record on reinstall, not just empty
    ///      the sets.
    struct AccountRegistry {
        mapping(bytes32 keyHash => Key) keys;
        mapping(uint256 purpose => EnumerableSet.Bytes32Set) byPurpose;
        EnumerableSet.Bytes32Set allKeys;
    }

    /// @dev One registry per account. Singleton deployment shared across all installers.
    /// @custom:storage-location erc7201:onchainid.validators.erc734-validator
    struct ModuleStorage {
        mapping(address account => AccountRegistry) registries;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("onchainid.validators.erc734-validator")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _MODULE_STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256(bytes("onchainid.validators.erc734-validator"))) - 1)
    ) & ~bytes32(uint256(0xff));

    error KeyAlreadyRegistered(bytes32 keyHash);
    error KeyNotRegistered(bytes32 keyHash);
    error InvalidSignerLength();
    error CannotRemoveLastManagementKey();
    /// @dev A registered key's `keyType` differs from the one supplied on re-purpose.
    error KeyTypeMismatch(bytes32 keyHash);
    /// @dev This validator only holds authorization purposes (MANAGEMENT / ACTION / PROPOSER).
    ///      Identity purposes (CLAIM_SIGNER / CLAIM_ADDER / ENCRYPTION) live on the account's
    ///      KeyManager so ERC-735 can read them; registering them here would be silently invisible.
    error NotAnAuthorizationPurpose(uint256 purpose);

    event KeyAdded(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose, uint256 keyType);
    event KeyRemoved(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose);

    // --- installation ----------------------------------------------------

    /// @dev Clears any leftover state from a prior install, then seeds the registry with a
    ///      single MANAGEMENT key from `data` (an ERC-7913 signer blob). keyType is inferred by
    ///      length; clientData is empty at install.
    ///
    ///      Cleanup happens here, not in {onUninstall}: OZ's `AccountERC7579._uninstallModule`
    ///      calls `onUninstall` with `callNoReturn`, so an aggressive gas estimator can starve
    ///      that subcall and skip it while the outer uninstall still succeeds. Doing the wipe on
    ///      (re)install means a stale registry can never leak into a fresh install regardless of
    ///      whether `onUninstall` ran.
    function onInstall(bytes calldata data) public virtual override {
        _clearRegistry(msg.sender);
        _addKey(
            msg.sender,
            data,
            "",
            KeyPurposes.MANAGEMENT,
            data.length == 20 ? 1 /* ECDSA */  : 3 /* WEBAUTHN */
        );
    }

    /// @dev No-op by design. Cleanup lives in {onInstall} instead, because this hook can be
    ///      bypassed by a gas-starved `callNoReturn` (see {onInstall}). Relying on it to clear
    ///      state would leave the registry populated after a bypassed uninstall; a reinstall
    ///      wipes it anyway. Uninstalling without reinstalling leaves the old keys dormant, which
    ///      is harmless: the account no longer routes to this validator once it is uninstalled.
    function onUninstall(
        bytes calldata /* data */
    )
        public
        virtual
        override
    { }

    /// @dev Wipes every `Key` record, every byPurpose entry, and the key index for `account`.
    ///      Each `Key.purposes` is an EnumerableSet, so it is `.clear()`ed explicitly: a plain
    ///      `delete keys[keyHash]` would leave the set's `_positions` mapping behind (see the
    ///      warning in OZ's EnumerableSet), which would corrupt a later re-registration.
    function _clearRegistry(address account) private {
        AccountRegistry storage registry = _store().registries[account];
        bytes32[] memory keyHashes = registry.allKeys.values();
        for (uint256 i = 0; i < keyHashes.length; i++) {
            Key storage key = registry.keys[keyHashes[i]];
            key.purposes.clear();
            delete key.keyType;
            delete key.signerData;
            delete key.clientData;
        }
        // Only the authorization purposes are ever populated here (see _isAuthorizationPurpose).
        registry.byPurpose[KeyPurposes.MANAGEMENT].clear();
        registry.byPurpose[KeyPurposes.ACTION].clear();
        registry.byPurpose[KeyPurposes.PROPOSER].clear();
        registry.allKeys.clear();
    }

    // --- registry (called by the account on itself) ----------------------

    /// @notice Register a key for the caller. Equivalent to `KeyManager.addKeyWithData`:
    ///         `keyHash` is `keccak256(signerData)`, and signerData/clientData are stored.
    /// @param signerData ERC-7913 signer bytes.
    /// @param clientData Non-cryptographic per-key metadata (e.g. WebAuthn credentialId).
    /// @param purpose Purpose to grant.
    /// @param keyType ECDSA / RSA / WEBAUTHN / MODULE.
    function addKey(bytes calldata signerData, bytes calldata clientData, uint256 purpose, uint256 keyType) external {
        _addKey(msg.sender, signerData, clientData, purpose, keyType);
    }

    /// @notice Remove a purpose from a key for the caller. The last MANAGEMENT key cannot be
    ///         removed. Deletes the record once its last purpose is gone.
    function removeKey(bytes32 keyHash, uint256 purpose) external {
        AccountRegistry storage registry = _store().registries[msg.sender];
        require(registry.allKeys.contains(keyHash), KeyNotRegistered(keyHash));
        Key storage key = registry.keys[keyHash];

        if (purpose == KeyPurposes.MANAGEMENT) {
            require(registry.byPurpose[KeyPurposes.MANAGEMENT].length() > 1, CannotRemoveLastManagementKey());
        }
        key.purposes.remove(purpose);
        registry.byPurpose[purpose].remove(keyHash);
        if (key.purposes.length() == 0) {
            delete registry.keys[keyHash];
            registry.allKeys.remove(keyHash);
        }

        emit KeyRemoved(msg.sender, keyHash, purpose);
    }

    /// @notice `IERC734.keyHasPurpose`, scoped to `account`. MANAGEMENT satisfies any purpose.
    function keyHasPurpose(address account, bytes32 keyHash, uint256 purpose) public view returns (bool) {
        AccountRegistry storage registry = _store().registries[account];
        if (registry.keys[keyHash].signerData.length == 0) return false;
        return registry.keys[keyHash].purposes.contains(purpose)
            || registry.keys[keyHash].purposes.contains(KeyPurposes.MANAGEMENT);
    }

    /// @notice Purposes held by `keyHash` on `account`.
    function getKeyPurposes(address account, bytes32 keyHash) external view returns (uint256[] memory) {
        return _store().registries[account].keys[keyHash].purposes.values();
    }

    /// @notice Key hashes with `purpose` on `account`.
    function getKeysByPurpose(address account, uint256 purpose) external view returns (bytes32[] memory) {
        return _store().registries[account].byPurpose[purpose].values();
    }

    /// @notice `KeyManager.getKeyData` for `account`: the signerData/clientData a key carries.
    function getKeyData(address account, bytes32 keyHash)
        external
        view
        returns (bytes memory signerData, bytes memory clientData)
    {
        Key storage key = _store().registries[account].keys[keyHash];
        return (key.signerData, key.clientData);
    }

    /// @notice `IERC734.getKey` for `account`.
    function getKey(address account, bytes32 keyHash)
        external
        view
        returns (uint256[] memory purposes, uint256 keyType, bytes32 key)
    {
        Key storage stored = _store().registries[account].keys[keyHash];
        return (stored.purposes.values(), stored.keyType, stored.signerData.length == 0 ? bytes32(0) : keyHash);
    }

    // --- validation ------------------------------------------------------

    /// @dev Crypto + membership. Verifies the signer signed `hash` and is a registered key on
    ///      `account`. The 1271 path stops here (no callData); userOps also run scoping in
    ///      {_validateUserOp}.
    function _rawERC7579Validation(address account, bytes32 hash, bytes calldata moduleSignature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        (bytes memory signer, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        if (signer.length < 20) return false;
        if (!_verify(signer, hash, signature)) return false;

        bytes32 keyHash = keccak256(signer);
        return _store().registries[account].keys[keyHash].signerData.length != 0;
    }

    /// @dev Adds per-target scoping on top of crypto + membership. The account routes
    ///      `validateUserOp` here through the base contract.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        virtual
        override
        returns (uint256)
    {
        if (!_rawERC7579Validation(userOp.sender, userOpHash, userOp.signature)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        (bytes memory signer,) = abi.decode(userOp.signature, (bytes, bytes));
        if (!_scopeAllows(userOp.sender, keccak256(signer), userOp.callData)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        return ERC4337Utils.SIG_VALIDATION_SUCCESS;
    }

    // --- internal --------------------------------------------------------

    /// @dev Whether the signer may run this userOp. Decodes `execute(mode, executionCalldata)`,
    ///      then applies {_targetAllowed} to the single call or to every call in a batch. Only
    ///      the standard `execute(bytes32,bytes)` selector is accepted; unknown call types fail.
    function _scopeAllows(address account, bytes32 keyHash, bytes calldata callData) internal view returns (bool) {
        // MANAGEMENT passes everything.
        if (keyHasPurpose(account, keyHash, KeyPurposes.MANAGEMENT)) return true;

        if (callData.length < 4 || bytes4(callData[:4]) != IERC7579Execution.execute.selector) return false;

        (bytes32 modeWord, bytes calldata executionCalldata) = _decodeExecute(callData);
        (CallType callType,,,) = ERC7579Utils.decodeMode(Mode.wrap(modeWord));

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            if (executionCalldata.length < 52) return false;
            address target = address(bytes20(executionCalldata[:20]));
            bytes calldata inner = executionCalldata[52:];
            return _targetAllowed(account, keyHash, target, inner);
        }

        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            // Every call in the batch must pass. The weakest-authorized call gates the batch.
            Execution[] calldata batch = ERC7579Utils.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                if (!_targetAllowed(account, keyHash, batch[i].target, batch[i].callData)) return false;
            }
            return true;
        }

        return false;
    }

    /// @dev Purpose required for one (target, inner-call) pair. MANAGEMENT already short-circuited
    ///      in {_scopeAllows}, so this only decides the sub-MANAGEMENT cases:
    ///        target == this validator          -> MANAGEMENT only (self-guard, see below)
    ///        self + addClaim                    -> CLAIM_SIGNER or CLAIM_ADDER (read on the account)
    ///        self + removeClaim                 -> CLAIM_SIGNER (read on the account)
    ///        self, anything else                -> MANAGEMENT only
    ///        external target                    -> ACTION
    ///      Claim purposes are read from the ACCOUNT's KeyManager, not this registry: identity
    ///      purposes live there (dual registry).
    function _targetAllowed(address account, bytes32 keyHash, address target, bytes calldata inner)
        private
        view
        returns (bool)
    {
        if (target == address(0)) target = account; // OZ aliases target 0 to self.

        // Self-guard: a call to this validator can rotate its own registry (addKey, etc.).
        // Only MANAGEMENT may do that, and MANAGEMENT already passed in _scopeAllows, so any
        // non-MANAGEMENT signer reaching here must be rejected. Without this, an ACTION signer
        // could execute(validator, addKey(attacker, MANAGEMENT)) — external target, ACTION
        // suffices — and escalate itself.
        if (target == address(this)) return false;

        if (target != account) {
            return keyHasPurpose(account, keyHash, KeyPurposes.ACTION);
        }

        bytes4 innerSelector = inner.length >= 4 ? bytes4(inner[:4]) : bytes4(0);
        if (innerSelector == IERC735.addClaim.selector) {
            return IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER)
                || IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_ADDER);
        }
        if (innerSelector == IERC735.removeClaim.selector) {
            return IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER);
        }
        return false;
    }

    /// @dev Splits `execute(bytes32 mode, bytes executionCalldata)` calldata into its two args,
    ///      keeping `executionCalldata` as a calldata slice.
    function _decodeExecute(bytes calldata callData)
        private
        pure
        returns (bytes32 modeWord, bytes calldata executionCalldata)
    {
        modeWord = bytes32(callData[4:36]);
        uint256 dataOffset = uint256(bytes32(callData[36:68]));
        uint256 lenPos = 4 + dataOffset;
        uint256 dataLen = uint256(bytes32(callData[lenPos:lenPos + 32]));
        uint256 dataStart = lenPos + 32;
        executionCalldata = callData[dataStart:dataStart + dataLen];
    }

    /// @dev ERC-7913 dispatch: 20-byte signer = EOA/1271, longer = verifier+key. Uses the
    ///      ECDSA path directly instead of `SignatureChecker.isValidSignatureNow(bytes,...)` to
    ///      avoid its `signer.code.length` check, which violates ERC-7562 bundler validation rules.
    function _verify(bytes memory signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        if (signer.length == 20) {
            address signerAddr = address(bytes20(signer));
            if (SignatureChecker.isValidERC1271SignatureNow(signerAddr, hash, signature)) return true;
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
            return err == ECDSA.RecoverError.NoError && recovered == signerAddr;
        }
        address verifier = address(bytes20(Bytes.slice(signer, 0, 20)));
        bytes memory key = Bytes.slice(signer, 20);
        (bool success, bytes memory result) =
            verifier.staticcall(abi.encodeCall(IERC7913SignatureVerifier.verify, (key, hash, signature)));
        return success && result.length >= 32
            && abi.decode(result, (bytes32)) == bytes32(IERC7913SignatureVerifier.verify.selector);
    }

    function _addKey(
        address account,
        bytes memory signerData,
        bytes memory clientData,
        uint256 purpose,
        uint256 keyType
    ) internal {
        // An ERC-7913 signer is at least 20 bytes (a 20-byte EOA/1271 address, or verifier+key).
        // Checked here so every caller (onInstall, addKey) is covered by a single guard.
        require(signerData.length >= 20, InvalidSignerLength());

        // This validator only holds authorization purposes. Identity purposes belong on the
        // account's KeyManager, where ERC-735 reads them; accepting one here would let it be
        // set somewhere claim verification never looks.
        require(_isAuthorizationPurpose(purpose), NotAnAuthorizationPurpose(purpose));

        // keyHash is derived from signerData, so the record always commits to its own bytes.
        bytes32 keyHash = keccak256(signerData);
        AccountRegistry storage registry = _store().registries[account];
        Key storage key = registry.keys[keyHash];

        if (key.signerData.length == 0) {
            key.signerData = signerData;
            key.clientData = clientData;
            key.keyType = keyType;
            registry.allKeys.add(keyHash);
        } else {
            // Re-purposing an existing key: keep the stored type, reject a mismatch.
            require(key.keyType == keyType, KeyTypeMismatch(keyHash));
        }

        require(key.purposes.add(purpose), KeyAlreadyRegistered(keyHash));
        registry.byPurpose[purpose].add(keyHash);
        emit KeyAdded(account, keyHash, purpose, keyType);
    }

    /// @dev MANAGEMENT / ACTION / PROPOSER are the authorization purposes this validator owns.
    function _isAuthorizationPurpose(uint256 purpose) private pure returns (bool) {
        return purpose == KeyPurposes.MANAGEMENT || purpose == KeyPurposes.ACTION || purpose == KeyPurposes.PROPOSER;
    }

    function _store() private pure returns (ModuleStorage storage store) {
        bytes32 slot = _MODULE_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            store.slot := slot
        }
    }

}
