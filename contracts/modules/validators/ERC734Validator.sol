// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { ERC4337Utils } from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import { CallType, ERC7579Utils, Mode } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import { IERC7913SignatureVerifier } from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {
    Execution,
    IERC7579Execution,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Bytes } from "@openzeppelin/contracts/utils/Bytes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { IIdentityFactory } from "../../factory/IIdentityFactory.sol";
import { IClaimIssuer } from "../../interface/IClaimIssuer.sol";
import { IERC734 } from "../../interface/IERC734.sol";
import { IERC735 } from "../../interface/IERC735.sol";
import { IIdentity } from "../../interface/IIdentity.sol";
import { Errors } from "../../libraries/Errors.sol";
import { hashAddress } from "../../libraries/Hashing.sol";
import { IdentityTypes } from "../../libraries/IdentityTypes.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";
import { KeyTypes } from "../../libraries/KeyTypes.sol";
import { IReputationRegistry } from "../../reputation/IReputationRegistry.sol";
import { Structs } from "../../storage/Structs.sol";
import { SafeCalldataBatch } from "../../vendor/utils/SafeCalldataBatch.sol";
import { ERC7579Validator } from "./ERC7579Validator.sol";

/// @title ERC734Validator
/// @notice One module holding both the ERC-734 key registry (keys + purposes) and the ERC-735
///         claim registry. It is installed as a validator (userOp signature verification), and as
///         a fallback handler for the ERC-734 getters and the ERC-735 claim selectors, so the key
///         registry and the claims share one contract and one storage area.
///
///         The account calls `validateUserOp`; this module verifies the signature, checks the
///         signer is a registered key, and enforces the purpose the userOp needs.
///
///         Constraint: the scoping rule guards this module's own address, but it does not know
///         about other privileged targets (installed executors, fallback handlers). A userOp from
///         an ACTION signer that calls `execute(installedExecutor, ...)` reads as an external
///         target here, so ACTION suffices; the call then reaches the executor with
///         `msg.sender == account`. Executor and fallback modules must gate their own callers
///         rather than trust that reaching them implies authorization.
///
/// @dev userOp signature wire format: `abi.encode(bytes signer, bytes signature)`, where
///      `signer` is ERC-7913 (20 bytes = EOA/1271, longer = `verifier(20) || key`). Storage is
///      ERC-7201 namespaced.
contract ERC734Validator is ERC7579Validator, IERC735 {

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

    /// @dev ERC-734 key registry plus ERC-735 claim state, scoped to one account. `allKeys` is
    ///      the membership index backing `keyHasPurpose` and the getters. `byPurpose` enumerates
    ///      keys per purpose, with one exception: MODULE keys are kept out of the MANAGEMENT set
    ///      (see {_addKey}), so that set holds signer keys only. Module keys still appear under
    ///      every other purpose. `claims` / `claimsByTopic` / `revokedDigests` hold the claim
    ///      registry (see the claims section below).
    struct AccountRegistry {
        mapping(bytes32 keyHash => Key) keys;
        mapping(uint256 purpose => EnumerableSet.Bytes32Set) byPurpose;
        EnumerableSet.Bytes32Set allKeys;
        mapping(bytes32 claimId => Structs.Claim) claims;
        mapping(uint256 topic => EnumerableSet.Bytes32Set) claimsByTopic;
        mapping(bytes32 digest => bool) revokedDigests;
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
    /// @dev The purpose is outside the ERC-734 range 1..6.
    error InvalidPurpose(uint256 purpose);
    /// @dev The grantee is this module itself. See the guard in {_addKey}.
    error ModuleCannotBeKey();

    event KeyAdded(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose, uint256 keyType);
    event KeyRemoved(address indexed account, bytes32 indexed keyHash, uint256 indexed purpose);

    /// @dev EIP-712 typehash for `Claim`. The nested `ClaimData` type is appended per the EIP-712
    ///      rule for nested struct types.
    bytes32 internal constant _CLAIM_TYPEHASH = keccak256(
        "Claim(uint256 topic,address subject,ClaimData data)ClaimData(uint256 issuedAt,uint256 validUntil,bytes payload)"
    );

    /// @dev EIP-712 typehash for the nested `ClaimData` envelope.
    bytes32 internal constant _CLAIM_DATA_TYPEHASH =
        keccak256("ClaimData(uint256 issuedAt,uint256 validUntil,bytes payload)");

    /// @notice Emitted when a claim digest is marked revoked by the issuer. Holder-side removals
    ///         emit `ClaimRemoved` (from IERC735) instead.
    event ClaimRevoked(bytes32 indexed digest, address indexed issuer);

    /// @notice Emitted when `addClaimTo` successfully writes a claim to another identity.
    event ClaimAddedTo(address indexed identity, uint256 topic, bytes signature, Structs.ClaimData data);

    /// @notice Factory used by {addClaimByTrustedIssuer} to resolve a caller wallet to
    ///         its issuer identity and to confirm that identity came from the factory.
    IIdentityFactory public immutable factory;

    /// @notice Registry consulted by {addClaimByTrustedIssuer} to confirm the issuer
    ///         identity meets the global claim-add threshold.
    IReputationRegistry public immutable reputationRegistry;

    /// @param identityFactory Factory used to resolve a caller wallet to its issuer
    ///                        identity in {addClaimByTrustedIssuer}. Reverts on zero.
    /// @param registry Reputation registry consulted by {addClaimByTrustedIssuer}.
    ///                 Reverts on zero.
    constructor(address identityFactory, address registry) {
        require(identityFactory != address(0), Errors.ZeroAddress());
        require(registry != address(0), Errors.ZeroAddress());
        factory = IIdentityFactory(identityFactory);
        reputationRegistry = IReputationRegistry(registry);
    }

    // --- installation ----------------------------------------------------

    /// @dev Seeds the registry with a single MANAGEMENT key from `data` (an ERC-7913 signer
    ///      blob). keyType is inferred by length; clientData is empty at install.
    ///
    ///      The registry is durable on purpose. It is enshrined in the account implementation,
    ///      and {KeyManager} keeps reading it whether or not this module is installed, so an
    ///      install never wipes prior state: a reinstall resumes the existing registry (keys,
    ///      claims and revoked digests included), and stale keys are removed individually via
    ///      {removeKey}. The seed is idempotent so a reinstall may reuse the same signer.
    function onInstall(bytes calldata data) public virtual {
        // Empty data is an executor or fallback install (claims and the ERC-734 getters). There is
        // no key to seed, so it is a no-op; the registry is seeded by the validator install below.
        if (data.length == 0) return;

        // Reinstall with a signer that already holds MANAGEMENT: nothing to seed.
        if (_keyHasPurpose(msg.sender, keccak256(data), KeyPurposes.MANAGEMENT)) return;

        // keyType is stored metadata only; _verify dispatches on the signer length, not on this.
        // A 20-byte signer is an EOA (ECDSA=1). A longer one is a generic ERC-7913 verifier+key
        // blob; we can't tell WebAuthn from RSA by length, so we label the common case, WEBAUTHN=3.
        _addKey(msg.sender, data, "", KeyPurposes.MANAGEMENT, data.length == 20 ? 1 : 3);
    }

    /// @dev Works as a validator (userOp signatures), an executor (issuer claim flows), and a
    ///      fallback handler (the ERC-734 getters and ERC-735 claim selectors).
    function isModuleType(uint256 moduleTypeId) public pure virtual override returns (bool) {
        return super.isModuleType(moduleTypeId) || moduleTypeId == MODULE_TYPE_EXECUTOR
            || moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @dev No-op by design: the registry is durable (see {onInstall}), and this hook can be
    ///      bypassed by a gas-starved `callNoReturn` anyway, so nothing may depend on it running.
    ///      Uninstalling leaves the keys in place, which is intended: the enshrined registry
    ///      keeps serving the account's ERC-734 reads whether or not this module is installed.
    function onUninstall(
        bytes calldata /* data */
    )
        public
        virtual { }

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

    /// @notice Remove a purpose from a key for the caller. The last MANAGEMENT key that can
    ///         sign cannot be removed. Deletes the record once its last purpose is gone.
    /// @dev The MANAGEMENT index only holds signer keys (see {_addKey}), so its length is the
    ///      manager count. The guard is skipped for MODULE keys: they hold no signing
    ///      authority, so removing them can never strand the identity.
    function removeKey(bytes32 keyHash, uint256 purpose) external {
        AccountRegistry storage registry = _store().registries[msg.sender];
        require(registry.allKeys.contains(keyHash), KeyNotRegistered(keyHash));
        Key storage key = registry.keys[keyHash];

        if (purpose == KeyPurposes.MANAGEMENT && key.keyType != KeyTypes.MODULE) {
            require(registry.byPurpose[KeyPurposes.MANAGEMENT].length() > 1, CannotRemoveLastManagementKey());
        }
        // Revert if the key doesn't have this purpose.
        require(key.purposes.remove(purpose), Errors.KeyDoesNotHavePurpose(keyHash, purpose));
        registry.byPurpose[purpose].remove(keyHash);
        if (key.purposes.length() == 0) {
            delete registry.keys[keyHash];
            registry.allKeys.remove(keyHash);
        }

        emit KeyRemoved(msg.sender, keyHash, purpose);
    }

    /// @notice `IERC734.keyHasPurpose`, scoped to `account`. MANAGEMENT satisfies any purpose.
    function keyHasPurpose(address account, bytes32 keyHash, uint256 purpose) public view returns (bool) {
        return _keyHasPurpose(account, keyHash, purpose);
    }

    /// @dev Shared implementation for both `keyHasPurpose` overloads. MANAGEMENT satisfies any purpose.
    function _keyHasPurpose(address account, bytes32 keyHash, uint256 purpose) internal view returns (bool) {
        AccountRegistry storage registry = _store().registries[account];
        return registry.allKeys.contains(keyHash)
            && (registry.keys[keyHash].purposes.contains(purpose)
                || registry.keys[keyHash].purposes.contains(KeyPurposes.MANAGEMENT));
    }

    /// @notice Purposes held by `keyHash` on `account`. Returns the full set. Use the
    ///         `(account, keyHash, start, end)` overload for large sets.
    function getKeyPurposes(address account, bytes32 keyHash) public view returns (uint256[] memory) {
        return _getKeyPurposes(account, keyHash, 0, type(uint64).max);
    }

    /// @notice Paginated variant of {getKeyPurposes}. Returns purposes in the index range
    ///         `[start, end)`. `end` past the set size returns the available tail.
    function getKeyPurposes(address account, bytes32 keyHash, uint256 start, uint256 end)
        public
        view
        returns (uint256[] memory)
    {
        return _getKeyPurposes(account, keyHash, start, end);
    }

    /// @dev Shared implementation for every `getKeyPurposes` overload.
    function _getKeyPurposes(address account, bytes32 keyHash, uint256 start, uint256 end)
        internal
        view
        returns (uint256[] memory)
    {
        return _store().registries[account].keys[keyHash].purposes.values(start, end);
    }

    /// @notice Key hashes with `purpose` on `account`. Returns the full set. Use the
    ///         `(account, purpose, start, end)` overload for large sets. For MANAGEMENT the set
    ///         holds signer keys only; MODULE keys are left out (see {_addKey}). Use
    ///         {keyHasPurpose} to check a module key's authority.
    function getKeysByPurpose(address account, uint256 purpose) public view returns (bytes32[] memory) {
        return _getKeysByPurpose(account, purpose, 0, type(uint64).max);
    }

    /// @notice Paginated variant of {getKeysByPurpose}. Returns key hashes in the index range
    ///         `[start, end)`. `end` past the set size returns the available tail.
    function getKeysByPurpose(address account, uint256 purpose, uint256 start, uint256 end)
        public
        view
        returns (bytes32[] memory)
    {
        return _getKeysByPurpose(account, purpose, start, end);
    }

    /// @dev Shared implementation for every `getKeysByPurpose` overload.
    function _getKeysByPurpose(address account, uint256 purpose, uint256 start, uint256 end)
        internal
        view
        returns (bytes32[] memory)
    {
        return _store().registries[account].byPurpose[purpose].values(start, end);
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
        public
        view
        returns (uint256[] memory purposes, uint256 keyType, bytes32 key)
    {
        Key storage stored = _store().registries[account].keys[keyHash];
        return (stored.purposes.values(), stored.keyType, stored.signerData.length == 0 ? bytes32(0) : keyHash);
    }

    // --- ERC-734 getters, account taken from msg.sender ------------------
    // The standard ERC-734 read functions, without the account argument. When this module is a
    // fallback handler, msg.sender is the account, so each reuses the account-scoped version above.

    /// @notice ERC-734 keyHasPurpose for the calling account.
    function keyHasPurpose(bytes32 _key, uint256 _purpose) external view returns (bool) {
        return _keyHasPurpose(msg.sender, _key, _purpose);
    }

    /// @notice ERC-734 getKeyPurposes for the calling account. Returns the full set. Use the
    ///         `(_key, start, end)` overload for large sets.
    function getKeyPurposes(bytes32 _key) external view returns (uint256[] memory) {
        return _getKeyPurposes(msg.sender, _key, 0, type(uint64).max);
    }

    /// @notice Paginated variant of {getKeyPurposes} for the calling account.
    function getKeyPurposes(bytes32 _key, uint256 start, uint256 end) external view returns (uint256[] memory) {
        return _getKeyPurposes(msg.sender, _key, start, end);
    }

    /// @notice ERC-734 getKeysByPurpose for the calling account. Returns the full set. Use the
    ///         `(_purpose, start, end)` overload for large sets. For MANAGEMENT the set holds
    ///         signer keys only; MODULE keys are left out (see {_addKey}).
    function getKeysByPurpose(uint256 _purpose) external view returns (bytes32[] memory) {
        return _getKeysByPurpose(msg.sender, _purpose, 0, type(uint64).max);
    }

    /// @notice Paginated variant of {getKeysByPurpose} for the calling account.
    function getKeysByPurpose(uint256 _purpose, uint256 start, uint256 end) external view returns (bytes32[] memory) {
        return _getKeysByPurpose(msg.sender, _purpose, start, end);
    }

    /// @notice ERC-734 getKey for the calling account.
    function getKey(bytes32 _key) external view returns (uint256[] memory purposes, uint256 keyType, bytes32 key) {
        return getKey(msg.sender, _key);
    }

    // --- validation ------------------------------------------------------

    /// @dev Verifies the signer is a registered key on `account`, then that it signed `hash`.
    ///      Membership is checked first so an unknown key skips signature verification. The 1271
    ///      path stops here; userOps also run scoping in {_validateUserOp}.
    function _rawERC7579Validation(address account, bytes32 hash, bytes calldata moduleSignature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        (bytes memory signer, bytes memory signature) = abi.decode(moduleSignature, (bytes, bytes));
        bytes32 keyHash = keccak256(signer);
        AccountRegistry storage registry = _store().registries[account];

        // The signer must be a registered key (a too-short signer can't be in `allKeys`), and it
        // must not be a MODULE key: those belong to installed modules (like KAM) and only gate what
        // a module can do, so they must never sign a user op or a 1271 signature. Then verify.
        return registry.allKeys.contains(keyHash) && registry.keys[keyHash].keyType != KeyTypes.MODULE
            && _verify(signer, hash, signature);
    }

    /// @dev ERC-1271. Only a key that can act for the account may sign as the account. We require
    ///      ACTION, which MANAGEMENT also satisfies. Claim, encryption and proposer keys are
    ///      registered but hold no signing authority, so they are rejected here. The crypto and
    ///      membership check itself is left to super via {_rawERC7579Validation}.
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        public
        view
        virtual
        override
        returns (bytes4)
    {
        (bytes memory signer,) = abi.decode(signature, (bytes, bytes));
        if (!_keyHasPurpose(msg.sender, keccak256(signer), KeyPurposes.ACTION)) return bytes4(0xffffffff);
        return super.isValidSignatureWithSender(sender, hash, signature);
    }

    /// @dev Adds per-target scoping on top of crypto + membership. The account routes
    ///      `validateUserOp` here through the base contract.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256)
    {
        // Super does the crypto + membership check; we add the per-target scoping on top.
        // Keep super's return value: it may pack an aggregator or time bounds, not just success.
        uint256 validationData = super._validateUserOp(userOp, userOpHash);
        if (validationData == ERC4337Utils.SIG_VALIDATION_FAILED) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        (bytes memory signer,) = abi.decode(userOp.signature, (bytes, bytes));
        if (!_scopeAllows(userOp.sender, keccak256(signer), userOp.callData)) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        return validationData;
    }

    // --- internal --------------------------------------------------------

    /// @dev Whether the signer may run this userOp. Decodes `execute(mode, executionCalldata)`,
    ///      then applies {_targetAllowed} to the single call or to every call in a batch. Only
    ///      the standard `execute(bytes32,bytes)` selector is accepted; unknown call types fail.
    function _scopeAllows(address account, bytes32 keyHash, bytes calldata callData) internal view returns (bool) {
        // MANAGEMENT passes everything.
        if (_keyHasPurpose(account, keyHash, KeyPurposes.MANAGEMENT)) return true;

        // Short calldata zero-pads and can't match the execute selector.
        if (bytes4(callData) != IERC7579Execution.execute.selector) return false;

        (Mode mode, bytes calldata executionCalldata) = _decodeExecute(callData);
        (CallType callType,,,) = ERC7579Utils.decodeMode(mode);

        if (callType == ERC7579Utils.CALLTYPE_SINGLE) {
            // A single execution is at least 52 bytes (20 target + 32 value).
            if (executionCalldata.length < 52) return false;
            (address target,,) = ERC7579Utils.decodeSingle(executionCalldata);
            return _targetAllowed(account, keyHash, target);
        }

        if (callType == ERC7579Utils.CALLTYPE_BATCH) {
            // Every call in the batch must pass. {SafeCalldataBatch} keeps the batch in calldata but
            // validates each entry against the slice bounds, so a backward offset can't point past
            // the batch and make us read a different target than the account runs. The account
            // decodes the same way, so the two checks always agree.
            Execution[] calldata batch = SafeCalldataBatch.decodeBatch(executionCalldata);
            for (uint256 i = 0; i < batch.length; i++) {
                if (!_targetAllowed(account, keyHash, batch[i].target)) return false;
            }
            return true;
        }

        return false;
    }

    /// @dev Purpose required for one (target, inner-call) pair. MANAGEMENT already short-circuited
    ///      in {_scopeAllows}, so this only decides the sub-MANAGEMENT cases:
    ///        target == this module             -> MANAGEMENT only (self-guard, see below)
    ///        self + addClaim                    -> CLAIM_SIGNER or CLAIM_ADDER (read on the account)
    ///        self + removeClaim                 -> CLAIM_SIGNER (read on the account)
    ///        self, anything else                -> MANAGEMENT only
    ///        external target                    -> ACTION
    ///      Claim purposes are read from this module's per-account registry (the same storage that
    ///      holds the keys), so the check works the same for any identity, including cross-identity
    ///      claim issuers.
    function _targetAllowed(address account, bytes32 keyHash, address target) private view returns (bool) {
        if (target == address(0)) target = account; // OZ aliases target 0 to self.

        // Self-guard: a call to this validator can rotate its own registry (addKey, etc.).
        // Only MANAGEMENT may do that, and MANAGEMENT already passed in _scopeAllows, so any
        // non-MANAGEMENT signer reaching here must be rejected. Without this, an ACTION signer
        // could execute(validator, addKey(attacker, MANAGEMENT)), an external target where ACTION
        // suffices, and escalate itself.
        if (target == address(this)) return false;

        // Factory-guard: the factory's wallet-binding calls (linkAccount, revokeAccount,
        // confirmCrossChainLink) change the identity's own bindings and are management-grade.
        // The factory is an external target, so without this an ACTION key could, for example,
        // terminally revoke one of the identity's wallets. MANAGEMENT already passed, so reject.
        if (target == address(factory)) return false;

        // An external target needs ACTION. A self-targeted call (addKey, addClaim, etc.) needs
        // MANAGEMENT, which already passed in _scopeAllows, so a non-MANAGEMENT signer is rejected.
        // Claims are not addable through a user op: the account calls itself, so the ERC-2771 caller
        // seen by addClaim is the account, which holds no claim key. Claim keys add claims by
        // calling the identity directly, not through execute().
        if (target != account) return keyHasPurpose(account, keyHash, KeyPurposes.ACTION);
        return false;
    }

    /// @dev Splits `execute(bytes32 mode, bytes executionCalldata)` calldata into its two args,
    ///      keeping `executionCalldata` as a calldata slice.
    function _decodeExecute(bytes calldata callData)
        private
        pure
        returns (Mode mode, bytes calldata executionCalldata)
    {
        // Hand-rolled so `executionCalldata` stays a calldata slice (decodeSingle/decodeBatch below
        // need calldata); `abi.decode` would return memory. Reads the ABI head the same way the
        // decoder does: mode, then the offset/length of the bytes arg. Callers guard the length.
        mode = Mode.wrap(bytes32(callData[4:36]));
        uint256 dataOffset = uint256(bytes32(callData[36:68]));
        uint256 lenPos = 4 + dataOffset;
        uint256 dataLen = uint256(bytes32(callData[lenPos:lenPos + 32]));
        uint256 dataStart = lenPos + 32;
        executionCalldata = callData[dataStart:dataStart + dataLen];
    }

    /// @dev ERC-7913 dispatch: 20-byte signer = EOA/1271, longer = verifier+key. Uses the
    ///      ECDSA path directly instead of `SignatureChecker.isValidSignatureNow(bytes,...)` to
    ///      avoid its `signer.code.length` check, which violates ERC-7562 bundler validation rules.
    ///      That only helps the EOA fast path: a contract signer still falls through to the
    ///      ERC-1271 external call below, so ERC-1271 signers do incur an external call during
    ///      user-op validation.
    ///      Single definition of a valid signature for the whole module: the key path and the claim
    ///      path both go through here, so a signer that gains code (EIP-7702) can't be judged valid
    ///      by one and invalid by the other.
    function _verify(bytes memory signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        if (signer.length == 20) {
            address signerAddr = address(bytes20(signer));
            // Try ECDSA first: the common EOA case resolves with no external call at all.
            // A contract signer, whose sig isn't a valid ECDSA sig, falls through to 1271,
            // which does staticcall the signer — the no-external-call property is EOA-only.
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
            if (err == ECDSA.RecoverError.NoError && recovered == signerAddr) return true;
            return SignatureChecker.isValidERC1271SignatureNow(signerAddr, hash, signature);
        }
        address verifier = address(bytes20(Bytes.slice(signer, 0, 20)));
        bytes memory key = Bytes.slice(signer, 20);
        // Raw staticcall on purpose. A high-level call would revert on a codeless verifier in
        // THIS frame (outside any try/catch), and guarding that with an explicit code check
        // would put an EXTCODESIZE in the 4337 validation path, which strict ERC-7562 bundler
        // rules frown on. Here a codeless verifier just returns no data and fails the length
        // check. Only registered signers reach this call: membership is checked first, so an
        // arbitrary user op cannot even execute it with an unregistered verifier.
        (bool success, bytes memory result) =
            verifier.staticcall(abi.encodeCall(IERC7913SignatureVerifier.verify, (key, hash, signature)));
        // The length check is required: nothing here ABI-decodes the returndata, and
        // bytes-to-bytes32 pads on the RIGHT, so a verifier returning the 4 raw magic bytes
        // would otherwise pass the compare. Verifiers must ABI-encode their bytes4 return.
        return success && result.length >= 32 && bytes32(result) == bytes32(IERC7913SignatureVerifier.verify.selector);
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

        // The module owns every ERC-734 purpose (1..6). Reject anything out of range.
        require(_isValidPurpose(purpose), InvalidPurpose(purpose));

        // keyHash is derived from signerData, so the record always commits to its own bytes.
        bytes32 keyHash = keccak256(signerData);

        // This module is one shared singleton, and addClaim treats its own address as "the call
        // came from addClaimTo". A key granted to the module itself would act as a claim key for
        // every issuer at once, so reject it here instead of trusting admins to never grant one.
        // This also makes initialize revert if this module is installed with a non-zero purpose.
        require(keyHash != hashAddress(address(this)), ModuleCannotBeKey());
        AccountRegistry storage registry = _store().registries[account];
        Key storage key = registry.keys[keyHash];

        if (registry.allKeys.add(keyHash)) {
            key.signerData = signerData;
            key.clientData = clientData;
            key.keyType = keyType;
        } else {
            // Re-purposing an existing key: keep the stored type, reject a mismatch.
            require(key.keyType == keyType, KeyTypeMismatch(keyHash));
        }

        require(key.purposes.add(purpose), KeyAlreadyRegistered(keyHash));
        // Module keys never enter the MANAGEMENT index. They cannot sign (the validator
        // rejects MODULE keys), so they must not count as managers. The last-manager guard
        // in removeKey and the factory's post-deploy check both rely on this index.
        // keyHasPurpose reads the key's own purpose set, so module authority is unchanged.
        // MANAGEMENT is the only purpose treated this way: its enumeration gates last-key
        // removal. Module keys still index under every other purpose.
        if (purpose != KeyPurposes.MANAGEMENT || key.keyType != KeyTypes.MODULE) {
            registry.byPurpose[purpose].add(keyHash);
        }
        emit KeyAdded(account, keyHash, purpose, keyType);
    }

    /// @dev The six ERC-734 purposes this module holds (1..6).
    function _isValidPurpose(uint256 purpose) private pure returns (bool) {
        return purpose >= KeyPurposes.MANAGEMENT && purpose <= KeyPurposes.PROPOSER;
    }

    // --- ERC-735 claims --------------------------------------------------
    // The claim registry, folded into this module so keys and claims share one contract. Claim
    // state lives per account in the same registry as the keys. Reached via the account's fallback,
    // so msg.sender is the identity and _msgSender() is the off-chain caller (ERC-2771 tail).
    //
    // So the key holder has to call these directly. If the call arrives any other way, for example
    // relayed by the EntryPoint or dispatched by the account itself through an executor, nothing is
    // appended, the recovered caller holds no claim key, and the call is refused. These entry
    // points cannot be used through a meta-transaction.

    /// @inheritdoc IERC735
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes memory _signature,
        Structs.ClaimData memory _data,
        string memory _uri
    ) public returns (bytes32 claimRequestId) {
        // CLAIM_SIGNER or CLAIM_ADDER can add a claim. Self-issued claims still need a real
        // signature (checked by isClaimValid in _addClaim), so CLAIM_ADDER cannot fake
        // self-attestations.
        address caller = _msgSender();
        // If the caller is this module itself, the call came from {addClaimTo}: the module made
        // the outbound call, so the target's fallback appended the module's own address as the
        // ERC-2771 caller. addClaimTo already checked that a MANAGEMENT key of `_issuer` started
        // the flow and that a CLAIM_SIGNER of `_issuer` signed the claim, so the claim-key check
        // below runs against `_issuer` instead.
        //
        // {addClaimTo} is the only path that can produce this caller. The other candidates are
        // closed: `execute(module, ...)` is blocked by the account's own-module guard
        // (Errors.OwnModuleTargetBlocked in SmartAccount), a direct call to the module with a
        // forged calldata tail only reaches the caller's own registry entry (msg.sender selects
        // the registry), and every other outbound call this module makes is a staticcall. As a
        // last line of defense, {_addKey} rejects the module's own address as a grantee. A new
        // state-changing outbound call added to this module must revisit this rebind.
        if (caller == address(this)) caller = _issuer;
        _requireClaimKey(msg.sender, caller, false);
        return _addClaim(msg.sender, _topic, _scheme, _issuer, _signature, _data, _uri);
    }

    /// @notice Add a claim without holding a CLAIM_ADDER / CLAIM_SIGNER key on the target
    ///         identity, by proving the caller is a trusted issuer in the {ReputationRegistry}.
    ///
    ///         Trust check (see {_requireTrustedIssuer}):
    ///           1. The caller's wallet resolves through the factory to a non-zero issuer
    ///              identity (i.e. the wallet is a linked account on a factory-deployed
    ///              identity).
    ///           2. `_issuer` equals that resolved identity. A trusted issuer cannot ship a
    ///              claim attributed to a different issuer.
    ///           3. The identity self-declares type CLAIM_ISSUER.
    ///           4. The issuer's score in the registry meets the global claim-add threshold.
    ///
    ///         When all four hold the rest of the flow is identical to {addClaim}: the issuer's
    ///         `isClaimValid` confirms the signature, the storage write happens, and
    ///         `ClaimAdded` / `ClaimChanged` fires. Removal is not exposed via this path.
    function addClaimByTrustedIssuer(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes memory _signature,
        Structs.ClaimData memory _data,
        string memory _uri
    ) public returns (bytes32 claimRequestId) {
        _requireTrustedIssuer(_msgSender(), _issuer);
        return _addClaim(msg.sender, _topic, _scheme, _issuer, _signature, _data, _uri);
    }

    /// @dev Shared write path for `addClaim` and `addClaimByTrustedIssuer`. The issuer-side
    ///      `isClaimValid` is called unconditionally; the storage write and event match the
    ///      standard `addClaim` body. Claim id is (issuer, topic); re-adding overwrites.
    function _addClaim(
        address account,
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes memory signature,
        Structs.ClaimData memory data,
        string memory uri
    ) internal returns (bytes32 claimId) {
        // removeClaim reads a claim's topic and treats 0 as "no such claim". So a claim stored
        // under topic 0 could never be removed. Reject it up front.
        require(topic != 0, Errors.InvalidClaimTopic());
        require(IClaimIssuer(issuer).isClaimValid(IIdentity(account), topic, signature, data), Errors.InvalidClaim());

        AccountRegistry storage s = _store().registries[account];
        claimId = keccak256(abi.encode(issuer, topic));
        s.claims[claimId] =
            Structs.Claim({ topic: topic, scheme: scheme, issuer: issuer, signature: signature, data: data, uri: uri });

        if (s.claimsByTopic[topic].add(claimId)) {
            emit ClaimAdded(claimId, topic, scheme, issuer, signature, data, uri);
        } else {
            emit ClaimChanged(claimId, topic, scheme, issuer, signature, data, uri);
        }
    }

    /// @dev Trusted-issuer gate. Four conditions, all required:
    ///        1. The caller wallet resolves through the factory to a non-zero issuer identity
    ///           (i.e. it is a linked account on a factory-deployed identity).
    ///        2. That identity equals the claim's declared issuer (issuer-bound rule).
    ///        3. That identity self-declares type `CLAIM_ISSUER`. Without this, any identity
    ///           that happens to be scored above the threshold (e.g. an INDIVIDUAL elevated by
    ///           the manager) could write claims silently.
    ///        4. Its reputation in the registry meets the global claim-add threshold.
    ///      `reputationOf` already returns `0` for non-factory identities, so the score check
    ///      implicitly re-confirms factory membership.
    function _requireTrustedIssuer(address caller, address expectedIssuer) internal view {
        address callerIdentity = factory.getIdentity(InteroperableAddress.formatEvmV1(block.chainid, caller));
        require(callerIdentity != address(0), Errors.CallerNotLinkedToFactoryIdentity(caller));
        require(expectedIssuer == callerIdentity, Errors.DeclaredIssuerMismatch(expectedIssuer, callerIdentity));
        require(
            IIdentity(callerIdentity).getIdentityType() == IdentityTypes.CLAIM_ISSUER,
            Errors.IdentityNotClaimIssuerType(callerIdentity)
        );
        IReputationRegistry registry = reputationRegistry;
        uint128 score = registry.reputationOf(callerIdentity);
        uint128 threshold = registry.claimAddThreshold();
        require(score >= threshold, Errors.ReputationBelowClaimAddThreshold(callerIdentity, score, threshold));
    }

    /// @inheritdoc IERC735
    /// @dev Marks the removed claim's digest revoked. Issuers backed by this module then refuse
    ///      the same (issuer, topic, ClaimData) and must sign a fresh claim to re-attest.
    function removeClaim(bytes32 _claimId) public returns (bool success) {
        address account = msg.sender;
        // CLAIM_ADDER cannot remove; only CLAIM_SIGNER (or self-call) is accepted here.
        _requireClaimKey(account, _msgSender(), true);

        AccountRegistry storage s = _store().registries[account];
        Structs.Claim storage c = s.claims[_claimId];
        uint256 topic = c.topic;
        require(topic != 0, Errors.ClaimNotRegistered(_claimId));

        // Revoke the digest on both the holder's and the issuer's sets so _getClaimStatus (which
        // reads the issuer's set) blocks re-adding the same bytes. Marking an already marked
        // digest is fine: an outside issuer can accept the same claim again, and that one still
        // has to be removable. The topic check above already rejects a double removal.
        bytes32 digest = _getClaimDigest(c.issuer, account, topic, c.data);
        s.revokedDigests[digest] = true;
        _store().registries[c.issuer].revokedDigests[digest] = true;

        s.claimsByTopic[topic].remove(_claimId);
        emit ClaimRemoved(_claimId, topic, c.scheme, c.issuer, c.signature, c.data, c.uri);
        delete s.claims[_claimId];

        return true;
    }

    /// @inheritdoc IERC735
    function getClaim(bytes32 _claimId)
        public
        view
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            Structs.ClaimData memory data,
            string memory uri
        )
    {
        Structs.Claim storage claim = _store().registries[msg.sender].claims[_claimId];
        return (claim.topic, claim.scheme, claim.issuer, claim.signature, claim.data, claim.uri);
    }

    /// @inheritdoc IERC735
    function getClaimIdsByTopic(uint256 _topic) external view returns (bytes32[] memory claimIds) {
        return _store().registries[msg.sender].claimsByTopic[_topic].values();
    }

    /// @notice Paginated variant of {getClaimIdsByTopic} for identities with many claims per topic.
    function getClaimIdsByTopicPaginated(uint256 _topic, uint256 start, uint256 end)
        external
        view
        returns (bytes32[] memory)
    {
        return _store().registries[msg.sender].claimsByTopic[_topic].values(start, end);
    }

    /// @notice Mark a claim digest revoked. Issuer-side revocation entry point.
    function revokeClaimByDigest(bytes32 digest) external {
        address account = msg.sender;
        _requireManagement(account, _msgSender());
        require(!_store().registries[account].revokedDigests[digest], Errors.ClaimAlreadyRevoked());

        _store().registries[account].revokedDigests[digest] = true;
        emit ClaimRevoked(digest, account);
    }

    /// @notice True if `digest` was marked revoked by the calling issuer (via revoke or removal).
    function isDigestRevoked(bytes32 digest) public view returns (bool) {
        return _store().registries[msg.sender].revokedDigests[digest];
    }

    /// @notice Verify a claim against the calling identity (msg.sender is the issuer). Returns true
    ///         only when the status is Valid.
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, Structs.ClaimData calldata data)
        external
        view
        returns (bool)
    {
        return _getClaimStatus(msg.sender, _identity, claimTopic, sig, data) == IClaimIssuer.ClaimStatus.Valid;
    }

    /// @notice Detailed status for a claim (Revoked / Expired / NotYetValid / NotIssued /
    ///         BadSignature / Valid), for off-chain consumers that need a reason.
    function getClaimStatus(
        IIdentity _identity,
        uint256 claimTopic,
        bytes calldata sig,
        Structs.ClaimData calldata data
    ) external view returns (IClaimIssuer.ClaimStatus) {
        return _getClaimStatus(msg.sender, _identity, claimTopic, sig, data);
    }

    /// @notice Off-chain helper: the EIP-712 hash a signer should sign for a claim against
    ///         `_identity` on the calling issuer's domain.
    function getClaimHash(address _identity, uint256 _topic, Structs.ClaimData memory _data)
        external
        view
        returns (bytes32)
    {
        return _getClaimDigest(msg.sender, _identity, _topic, _data);
    }

    /// @notice Verify a claim then write it to the target identity via its `addClaim`. The target
    ///         must have granted the calling issuer identity a CLAIM_SIGNER or CLAIM_ADDER key.
    function addClaimTo(
        uint256 _topic,
        uint256 _scheme,
        bytes calldata _signature,
        Structs.ClaimData calldata _data,
        string calldata _uri,
        IIdentity _identity
    ) external {
        address account = msg.sender;
        _requireManagement(account, _msgSender());

        require(
            _getClaimStatus(account, _identity, _topic, _signature, _data) == IClaimIssuer.ClaimStatus.Valid,
            Errors.InvalidClaim()
        );

        // This call lands back in {addClaim} on the target, with this module as the ERC-2771
        // caller. addClaim detects that and checks the target's claim keys against `account`,
        // passed here as the issuer. Keep this the module's only state-changing external call
        // to an arbitrary address; the issuer rebinding in addClaim depends on it.
        _identity.addClaim(_topic, _scheme, account, _signature, _data, _uri);
        emit ClaimAddedTo(address(_identity), _topic, _signature, _data);
    }

    // --- claims internals ------------------------------------------------

    /// @dev Build the EIP-712 claim digest using the issuer identity's domain (read via IERC5267),
    ///      so signers sign against the issuer address, not this module.
    function _getClaimDigest(address account, address subject, uint256 topic, Structs.ClaimData memory data)
        internal
        view
        virtual
        returns (bytes32)
    {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = IERC5267(account).eip712Domain();

        bytes32 domainSeparator =
            MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt);

        bytes32 dataHash =
            keccak256(abi.encode(_CLAIM_DATA_TYPEHASH, data.issuedAt, data.validUntil, keccak256(data.payload)));
        bytes32 structHash = keccak256(abi.encode(_CLAIM_TYPEHASH, topic, subject, dataHash));
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /// @dev Detailed claim validity. Checks are ordered cheapest first: time bounds, revoked
    ///      digest, signature shape, CLAIM_SIGNER on the issuer, then cryptographic verification.
    function _getClaimStatus(
        address account,
        IIdentity _identity,
        uint256 topic,
        bytes memory sig,
        Structs.ClaimData memory data
    ) internal view virtual returns (IClaimIssuer.ClaimStatus) {
        if (data.issuedAt == 0) return IClaimIssuer.ClaimStatus.BadSignature;
        if (block.timestamp < data.issuedAt) return IClaimIssuer.ClaimStatus.NotYetValid;
        if (data.validUntil != 0 && block.timestamp > data.validUntil) return IClaimIssuer.ClaimStatus.Expired;

        bytes32 digest = _getClaimDigest(account, address(_identity), topic, data);
        if (_store().registries[account].revokedDigests[digest]) return IClaimIssuer.ClaimStatus.Revoked;

        // A `(bytes signer, bytes rawSig)` blob needs 2 offset words + 2 length words = 128 bytes
        // minimum before any data, so a shorter blob can't decode.
        if (sig.length < 128) return IClaimIssuer.ClaimStatus.BadSignature;
        (bytes memory signer, bytes memory rawSig) = abi.decode(sig, (bytes, bytes));
        if (signer.length < 20) return IClaimIssuer.ClaimStatus.BadSignature;
        if (!keyHasPurpose(account, keccak256(signer), KeyPurposes.CLAIM_SIGNER)) {
            return IClaimIssuer.ClaimStatus.NotIssued;
        }
        if (!_verify(signer, digest, rawSig)) {
            return IClaimIssuer.ClaimStatus.BadSignature;
        }
        return IClaimIssuer.ClaimStatus.Valid;
    }

    /// @dev Require the off-chain caller to hold a claim key on `account`. CLAIM_SIGNER covers add
    ///      and remove; CLAIM_ADDER is accepted only when `onlyClaimSigner` is false (addClaim).
    function _requireClaimKey(address account, address caller, bool onlyClaimSigner) internal view {
        bytes32 keyHash = hashAddress(caller);

        if (keyHasPurpose(account, keyHash, KeyPurposes.CLAIM_SIGNER)) return;
        if (!onlyClaimSigner && keyHasPurpose(account, keyHash, KeyPurposes.CLAIM_ADDER)) return;

        revert Errors.SenderDoesNotHaveClaimSignerKey();
    }

    /// @dev Require the off-chain caller to hold MANAGEMENT on `account`.
    function _requireManagement(address account, address caller) internal view {
        require(
            keyHasPurpose(account, hashAddress(caller), KeyPurposes.MANAGEMENT), Errors.SenderDoesNotHaveManagementKey()
        );
    }

    /// @dev When reached through the account's ERC-7579 fallback, msg.sender is the identity and
    ///      the real caller is the last 20 bytes of calldata (ERC-2771).
    /// @dev The length check only says a tail could fit, not that one was actually appended. On a
    ///      path that skips the fallback the last 20 bytes are just ABI arguments, so the caller
    ///      reads back as some address that holds no key and the call is refused. We ask for a
    ///      selector plus the tail, so a call too short to carry one uses `msg.sender` instead.
    function _msgSender() internal view returns (address sender) {
        if (msg.data.length >= 24) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function _store() private pure returns (ModuleStorage storage store) {
        bytes32 slot = _MODULE_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            store.slot := slot
        }
    }

}
