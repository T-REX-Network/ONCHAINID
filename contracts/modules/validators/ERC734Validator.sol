// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { KeyPurposes } from "../../libraries/KeyPurposes.sol";
import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC734Validator
/// @notice Prototype. Holds the ERC-734 key registry (keys, purposes, and per-target scoping)
///         inside the validator instead of on the account, so the account only decides whether
///         a validator is authorized and never decodes the signature.
///
///         The account calls `validateUserOp`; this module verifies the signature, checks the
///         signer is a registered key, and enforces the purpose the userOp needs. The account
///         stays agnostic to the signature format.
///
///         Known limitation: ERC-735 claim verification reads `keyHasPurpose` on the identity
///         account, not on any validator (see `ClaimsModule._getClaimStatus`). A registry that
///         lives only here is invisible to that path, so the account still has to answer
///         `keyHasPurpose`. The test suite pins this.
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

    /// @dev ERC-734 key registry, scoped to one account.
    struct AccountRegistry {
        mapping(bytes32 keyHash => Key) keys;
        mapping(uint256 purpose => EnumerableSet.Bytes32Set) byPurpose;
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

    /// @dev Claim selectors a CLAIM_SIGNER / CLAIM_ADDER may self-target. Everything else
    ///      self-targeted (addKey, removeKey, ...) requires MANAGEMENT and needs no constant.
    bytes4 private constant _ADD_CLAIM_SELECTOR =
        bytes4(keccak256("addClaim(uint256,uint256,address,bytes,bytes,string)"));
    bytes4 private constant _REMOVE_CLAIM_SELECTOR = bytes4(keccak256("removeClaim(bytes32)"));

    error KeyAlreadyRegistered(bytes32 keyHash);
    error KeyNotRegistered(bytes32 keyHash);
    error InvalidSignerLength();
    error CannotRemoveLastManagementKey();
    /// @dev A registered key's `keyType` differs from the one supplied on re-purpose.
    error KeyTypeMismatch(bytes32 keyHash);

    event KeyAdded(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose, uint256 keyType);
    event KeyRemoved(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose);

    // --- installation ----------------------------------------------------

    /// @dev Seeds the registry with a single MANAGEMENT key from `data` (an ERC-7913 signer
    ///      blob). keyType is inferred by length; clientData is empty at install.
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 20, InvalidSignerLength());
        _addKey(
            msg.sender,
            data,
            "",
            KeyPurposes.MANAGEMENT,
            data.length == 20 ? 1 /* ECDSA */  : 3 /* WEBAUTHN */
        );
    }

    /// @dev Clears the caller's registry. Idempotent.
    function onUninstall(
        bytes calldata /* data */
    )
        public
        virtual
        override
    {
        AccountRegistry storage registry = _store().registries[msg.sender];
        // Empties the byPurpose sets; the Key structs are left orphaned. A shipping version
        // would track a per-account key set and delete each record.
        for (uint256 purpose = KeyPurposes.MANAGEMENT; purpose <= KeyPurposes.PROPOSER; purpose++) {
            bytes32[] memory keyHashes = registry.byPurpose[purpose].values();
            for (uint256 index = 0; index < keyHashes.length; index++) {
                registry.byPurpose[purpose].remove(keyHashes[index]);
            }
        }
    }

    // --- registry (called by the account on itself) ----------------------

    /// @notice Register a key for the caller. Equivalent to `KeyManager.addKeyWithData`:
    ///         `keyHash` is `keccak256(signerData)`, and signerData/clientData are stored.
    /// @param signerData ERC-7913 signer bytes.
    /// @param clientData Non-cryptographic per-key metadata (e.g. WebAuthn credentialId).
    /// @param purpose Purpose to grant.
    /// @param keyType ECDSA / RSA / WEBAUTHN / MODULE.
    function addKey(bytes calldata signerData, bytes calldata clientData, uint256 purpose, uint256 keyType) external {
        require(signerData.length >= 20, InvalidSignerLength());
        _addKey(msg.sender, signerData, clientData, purpose, keyType);
    }

    /// @notice Remove a purpose from a key for the caller. The last MANAGEMENT key cannot be
    ///         removed. Deletes the record once its last purpose is gone.
    function removeKey(bytes32 keyHash, uint256 purpose) external {
        AccountRegistry storage registry = _store().registries[msg.sender];
        Key storage key = registry.keys[keyHash];
        require(key.signerData.length != 0, KeyNotRegistered(keyHash));

        if (purpose == KeyPurposes.MANAGEMENT) {
            require(registry.byPurpose[KeyPurposes.MANAGEMENT].length() > 1, CannotRemoveLastManagementKey());
        }
        key.purposes.remove(purpose);
        registry.byPurpose[purpose].remove(keyHash);
        if (key.purposes.length() == 0) delete registry.keys[keyHash];

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

    /// @dev Purpose required for what the userOp does, matching `KeyApprovalModule._canAutoApprove`:
    ///        external target  -> ACTION
    ///        self + addClaim  -> CLAIM_SIGNER or CLAIM_ADDER
    ///        self + removeClaim -> CLAIM_SIGNER
    ///        self, anything else -> MANAGEMENT
    ///      MANAGEMENT passes everything.
    function _scopeAllows(address account, bytes32 keyHash, bytes calldata callData) internal view returns (bool) {
        if (keyHasPurpose(account, keyHash, KeyPurposes.MANAGEMENT)) return true;

        (address target, bytes4 innerSelector) = _decodeExecuteTarget(callData);
        if (target == address(0)) target = account; // OZ aliases target 0 to self.

        if (target != account) {
            return keyHasPurpose(account, keyHash, KeyPurposes.ACTION);
        }
        if (innerSelector == _ADD_CLAIM_SELECTOR) {
            return keyHasPurpose(account, keyHash, KeyPurposes.CLAIM_SIGNER)
                || keyHasPurpose(account, keyHash, KeyPurposes.CLAIM_ADDER);
        }
        if (innerSelector == _REMOVE_CLAIM_SELECTOR) {
            return keyHasPurpose(account, keyHash, KeyPurposes.CLAIM_SIGNER);
        }
        return false;
    }

    /// @dev Reads the target and inner selector out of `execute(bytes32,bytes)` callData.
    ///      Handles CALLTYPE_SINGLE only; batch is not covered by this prototype.
    function _decodeExecuteTarget(bytes calldata callData) internal pure returns (address target, bytes4 selector) {
        // execute(bytes32,bytes): [0:4] selector, [4:36] mode, [36:68] offset, then the bytes.
        if (callData.length < 68) return (address(0), bytes4(0));
        uint256 dataOffset = uint256(bytes32(callData[36:68]));
        uint256 lenPos = 4 + dataOffset;
        if (lenPos + 32 > callData.length) return (address(0), bytes4(0));
        uint256 dataStart = lenPos + 32;
        // SINGLE layout: target(20) value(32) data(...).
        if (dataStart + 52 > callData.length) return (address(0), bytes4(0));
        target = address(bytes20(callData[dataStart:dataStart + 20]));
        uint256 innerStart = dataStart + 52;
        if (innerStart + 4 <= callData.length) {
            selector = bytes4(callData[innerStart:innerStart + 4]);
        }
    }

    /// @dev ERC-7913 dispatch: 20-byte signer = EOA/1271, longer = verifier+key. Uses the
    ///      ECDSA path directly instead of `SignatureChecker.isValidSignatureNow(bytes,...)` to
    ///      avoid its code-length check under ERC-7562, matching {ERC7579Signature}.
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
        // keyHash is derived from signerData, so the record always commits to its own bytes.
        bytes32 keyHash = keccak256(signerData);
        AccountRegistry storage registry = _store().registries[account];
        Key storage key = registry.keys[keyHash];

        if (key.signerData.length == 0) {
            key.signerData = signerData;
            key.clientData = clientData;
            key.keyType = keyType;
        } else {
            // Re-purposing an existing key: keep the stored type, reject a mismatch.
            require(key.keyType == keyType, KeyTypeMismatch(keyHash));
        }

        require(key.purposes.add(purpose), KeyAlreadyRegistered(keyHash));
        registry.byPurpose[purpose].add(keyHash);
        emit KeyAdded(account, keyHash, purpose, keyType);
    }

    function _store() private pure returns (ModuleStorage storage store) {
        bytes32 slot = _MODULE_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            store.slot := slot
        }
    }

}

interface IERC7913SignatureVerifier {

    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external view returns (bytes4);

}
