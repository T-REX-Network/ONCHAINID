// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { IClaimIssuer } from "../../interface/IClaimIssuer.sol";
import { IERC734 } from "../../interface/IERC734.sol";
import { IERC735 } from "../../interface/IERC735.sol";
import { IIdentity } from "../../interface/IIdentity.sol";
import { Errors } from "../../libraries/Errors.sol";
import { KeyPurposes } from "../../libraries/KeyPurposes.sol";
import { Structs } from "../../storage/Structs.sol";

/**
 * @title ClaimsModule
 * @notice ERC-735 claim registry plus issuer functions (revoke, addClaimTo, isClaimValid, getClaimStatus).
 *         Installed on an Identity as an ERC-7579 fallback so calls to claim selectors on the identity
 *         land here.
 *
 * @dev    Per-identity storage. State is keyed by the calling identity (`msg.sender`), so one
 *         deployment serves every identity that installs it. EIP-712 digests are built from the
 *         calling identity's domain (read via IERC5267), so off-chain signers sign against the
 *         identity address — not against this module address.
 *
 *         Digest-based revocation. The issuer's `revokedDigests` set is the source of truth for
 *         "this claim is no longer eligible," read by `_getClaimStatus` during validation. A digest
 *         is marked revoked by the issuer (via `revokeClaimByDigest`) and by the holder (via
 *         `removeClaim`, which writes to BOTH the holder's and the issuer's sets so the issuer-side
 *         read sees it). Once revoked, the same `(issuer, topic, ClaimData)` cannot be re-added;
 *         the issuer must produce a fresh claim with different `ClaimData` (e.g. a bumped
 *         `issuedAt`) to re-attest.
 *
 *         Why digest, not signature bytes. Signatures are encoding-malleable in many ways
 *         (trailing zeros, ECDSA low-s siblings, fresh WebAuthn ceremonies, ERC-1271 internal
 *         randomness, re-signing with a different CLAIM_SIGNER). Keying revocation on the
 *         signature bytes lets every other valid witness for the same claim bypass the revoke.
 *         The EIP-712 digest is the same across every valid signature for the same claim and is
 *         therefore the right identifier.
 *
 *         Why distinct events. `ClaimRevoked` is emitted only on issuer-side revocation;
 *         `ClaimRemoved` is emitted only on holder-side removal. They share the revoked-set
 *         underneath but report different audit semantics to off-chain indexers.
 */
contract ClaimsModule is IERC7579Module, IERC735 {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @dev Per-identity claim state. Storage is keyed by the calling identity in `_state`,
     *      so one ClaimsModule deployment serves every identity that installs it.
     *
     *      claims:          claimId (= keccak256(issuer, topic)) → stored claim record.
     *      claimsByTopic:   topic → set of claimIds carrying that topic, for enumeration.
     *      revokedDigests:  EIP-712 claim digest → true once revoked. The issuer's set is the
     *                       canonical source for `_getClaimStatus`. `removeClaim` writes to
     *                       both the holder's and the issuer's sets to keep that invariant.
     */
    struct AccountState {
        mapping(bytes32 => Structs.Claim) claims;
        mapping(uint256 => EnumerableSet.Bytes32Set) claimsByTopic;
        mapping(bytes32 => bool) revokedDigests;
    }

    /// @dev Storage shared across all identities that install this module.
    mapping(address => AccountState) private _state;

    /// @dev EIP-712 typehash for `Claim`. The nested `ClaimData` type is appended per
    ///      the EIP-712 rule for nested struct types (alphabetical).
    bytes32 internal constant _CLAIM_TYPEHASH = keccak256(
        "Claim(uint256 topic,address subject,ClaimData data)ClaimData(uint256 issuedAt,uint256 validUntil,bytes payload)"
    );

    /// @dev EIP-712 typehash for the nested `ClaimData` envelope.
    bytes32 internal constant _CLAIM_DATA_TYPEHASH =
        keccak256("ClaimData(uint256 issuedAt,uint256 validUntil,bytes payload)");

    /**
     * @notice Emitted when a claim digest is marked revoked by the issuer.
     *         Holder-side removals emit `ClaimRemoved` (from IERC735) instead.
     */
    event ClaimRevoked(bytes32 indexed digest, address indexed issuer);

    /// @notice Emitted when `addClaimTo` successfully writes a claim to another identity.
    event ClaimAddedTo(address indexed identity, uint256 topic, bytes signature, Structs.ClaimData data);

    // -----------------------------------------------------------------------
    // ERC-7579 module metadata
    // -----------------------------------------------------------------------

    /**
     * @inheritdoc IERC7579Module
     * @return True when `moduleTypeId` is `MODULE_TYPE_EXECUTOR` or `MODULE_TYPE_FALLBACK`.
     */
    function isModuleType(uint256 moduleTypeId) public pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR || moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /**
     * @inheritdoc IERC7579Module
     * @dev No-op. Per-account storage is initialized lazily on first write.
     */
    function onInstall(bytes calldata) external pure { }

    /**
     * @inheritdoc IERC7579Module
     * @dev No-op. Existing claim and revoked-digest state on the uninstalling account is left in
     *      place so re-installing the module does not silently un-revoke previously revoked digests.
     */
    function onUninstall(bytes calldata) external pure { }

    // -----------------------------------------------------------------------
    // ERC-735 ABI — reached through the identity's fallback handler
    // -----------------------------------------------------------------------

    /**
     * @inheritdoc IERC735
     * @param _topic Topic of the claim (see ClaimTopics).
     * @param _scheme Signature scheme used by the issuer (1 = ECDSA).
     * @param _issuer Address of the issuer that signed the claim. May be the calling identity itself.
     * @param _signature Issuer's signature over the EIP-712 claim digest (wire format
     *                   `abi.encode(bytes signer, bytes rawSig)` where `signer` follows ERC-7913).
     * @param _data Typed claim envelope: `issuedAt`, `validUntil`, topic-specific `payload`.
     * @param _uri Optional off-chain URI with the claim contents.
     * @return claimRequestId `keccak256(abi.encode(_issuer, _topic))`. Also serves as the storage key.
     */
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes memory _signature,
        Structs.ClaimData memory _data,
        string memory _uri
    ) public override returns (bytes32 claimRequestId) {
        // When reached via fallback, msg.sender is the Identity and _msgSender() is the off-chain caller.
        address account = msg.sender;
        // CLAIM_SIGNER or CLAIM_ADDER can add a claim. Self-issued claims still need a real signature
        // (see the `isClaimValid` call below), so a CLAIM_ADDER cannot fabricate self-attestations.
        _requireClaimKey(
            account,
            _msgSender(),
            /* onlyClaimSigner */
            false
        );

        // Always ask the issuer to confirm — self-issued claims included. For external issuers
        // this is a cross-contract round trip. For self-issued claims the call routes back into
        // this module's `_getClaimStatus` on the same identity, enforcing the exact same rules
        // (CLAIM_SIGNER on issuer, signature valid for the digest, time bounds, digest not revoked).
        require(
            IClaimIssuer(_issuer).isClaimValid(IIdentity(account), _topic, _signature, _data), Errors.InvalidClaim()
        );

        // Claim id is `(issuer, topic)`. Adding the same id again overwrites the previous record.
        // The previous record is NOT counted as revoked — overwriting is an update, not a removal.
        AccountState storage s = _state[account];
        bytes32 claimId = keccak256(abi.encode(_issuer, _topic));
        s.claims[claimId] = Structs.Claim({
            topic: _topic, scheme: _scheme, issuer: _issuer, signature: _signature, data: _data, uri: _uri
        });

        // `EnumerableSet.add` returns true on first insert (emit ClaimAdded);
        // false when the id was already present (emit ClaimChanged).
        if (s.claimsByTopic[_topic].add(claimId)) {
            emit ClaimAdded(claimId, _topic, _scheme, _issuer, _signature, _data, _uri);
        } else {
            emit ClaimChanged(claimId, _topic, _scheme, _issuer, _signature, _data, _uri);
        }

        return claimId;
    }

    /**
     * @inheritdoc IERC735
     * @param _claimId Storage key returned by `addClaim`.
     * @return success True when the claim was found and removed.
     * @dev Marks the removed claim's digest as revoked. After `removeClaim`, the exact same
     *      `(issuer, topic, ClaimData)` cannot be re-added — the issuer must sign a fresh
     *      claim (varying `issuedAt`, `payload`, or `validUntil`) to re-attest.
     */
    function removeClaim(bytes32 _claimId) public override returns (bool success) {
        address account = msg.sender;
        // CLAIM_ADDER cannot remove; only CLAIM_SIGNER (or self-call) is accepted here.
        _requireClaimKey(
            account,
            _msgSender(),
            /* onlyClaimSigner */
            true
        );

        AccountState storage s = _state[account];
        Structs.Claim storage c = s.claims[_claimId];
        // Topic 0 means the slot is empty. Claims always carry a non-zero topic.
        uint256 topic = c.topic;
        require(topic != 0, Errors.ClaimNotRegistered(_claimId));

        // Mark the digest revoked while the fields are still in storage. Write to BOTH the
        // holder's and the issuer's revoked sets so `_getClaimStatus` (which reads the issuer's
        // set during validation) sees the removal and blocks re-adding the same bytes. The
        // holder-side write keeps a local record; the issuer-side write is what makes the rule
        // stick for external issuers.
        bytes32 digest = _getClaimDigest(c.issuer, account, topic, c.data);
        require(!s.revokedDigests[digest], Errors.ClaimAlreadyRevoked());
        s.revokedDigests[digest] = true;
        _state[c.issuer].revokedDigests[digest] = true;

        // Drop the topic index entry first so the event still has the claim fields available.
        s.claimsByTopic[topic].remove(_claimId);
        emit ClaimRemoved(_claimId, topic, c.scheme, c.issuer, c.signature, c.data, c.uri);
        delete s.claims[_claimId];

        return true;
    }

    /**
     * @inheritdoc IERC735
     * @param _claimId Storage key returned by `addClaim`.
     * @return topic Claim topic.
     * @return scheme Signature scheme used by the issuer.
     * @return issuer Address that signed the claim.
     * @return signature Issuer signature over the EIP-712 claim digest.
     * @return data Typed claim envelope (`issuedAt`, `validUntil`, `payload`).
     * @return uri Off-chain URI attached to the claim.
     */
    function getClaim(bytes32 _claimId)
        public
        view
        override
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            Structs.ClaimData memory data,
            string memory uri
        )
    {
        Structs.Claim storage claim = _state[msg.sender].claims[_claimId];
        return (claim.topic, claim.scheme, claim.issuer, claim.signature, claim.data, claim.uri);
    }

    /**
     * @inheritdoc IERC735
     * @param _topic Topic to enumerate.
     * @return claimIds Storage keys of every claim stored under `_topic` on the calling identity.
     */
    function getClaimIdsByTopic(uint256 _topic) external view override returns (bytes32[] memory claimIds) {
        return _state[msg.sender].claimsByTopic[_topic].values();
    }

    /**
     * @notice Paginated variant of {getClaimIdsByTopic}. Use this on identities with many
     *         claims under one topic to avoid hitting the block gas limit.
     * @param _topic Topic to enumerate.
     * @param start Index of the first claim to return.
     * @param end Index (exclusive) of the last claim to return.
     */
    function getClaimIdsByTopicPaginated(uint256 _topic, uint256 start, uint256 end)
        external
        view
        returns (bytes32[] memory)
    {
        return _state[msg.sender].claimsByTopic[_topic].values(start, end);
    }

    // -----------------------------------------------------------------------
    // ClaimIssuer extras
    // -----------------------------------------------------------------------

    /**
     * @notice Mark a claim digest as revoked. Canonical issuer-side revocation entry point — the
     *         issuer already knows the digest (or computed it via `getClaimHash`), so no claim
     *         lookup is required.
     * @param digest the EIP-712 claim digest to mark revoked.
     */
    function revokeClaimByDigest(bytes32 digest) external {
        address account = msg.sender;
        _requireManagement(account, _msgSender());
        require(!_state[account].revokedDigests[digest], Errors.ClaimAlreadyRevoked());

        _state[account].revokedDigests[digest] = true;
        emit ClaimRevoked(digest, account);
    }

    /**
     * @notice True if `digest` has been marked revoked by the calling issuer (via revoke or removal).
     * @param digest EIP-712 claim digest to look up in the calling issuer's revoked set.
     */
    function isDigestRevoked(bytes32 digest) public view returns (bool) {
        return _state[msg.sender].revokedDigests[digest];
    }

    /**
     * @notice Verify a claim against the calling identity (`msg.sender` is the issuer).
     * @dev Convenience wrapper that returns `true` only when status is `Valid`. Off-chain callers
     *      that need to distinguish failure modes (revoked vs expired vs bad signature) should use
     *      `getClaimStatus` instead.
     * @param _identity Subject identity the claim is about.
     * @param claimTopic Topic of the claim.
     * @param sig Signature produced by a CLAIM_SIGNER key of the issuer.
     * @param data Typed claim envelope that was signed.
     */
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, Structs.ClaimData calldata data)
        external
        view
        returns (bool)
    {
        return _getClaimStatus(msg.sender, _identity, claimTopic, sig, data) == IClaimIssuer.ClaimStatus.Valid;
    }

    /**
     * @notice Detailed status for a claim. Distinguishes `Revoked`, `Expired`, `NotYetValid`,
     *         `NotIssued`, and `BadSignature` — useful for off-chain consumers that need to
     *         surface a reason to users (e.g. "claim expired" vs "claim revoked").
     */
    function getClaimStatus(
        IIdentity _identity,
        uint256 claimTopic,
        bytes calldata sig,
        Structs.ClaimData calldata data
    ) external view returns (IClaimIssuer.ClaimStatus) {
        return _getClaimStatus(msg.sender, _identity, claimTopic, sig, data);
    }

    /**
     * @notice Off-chain helper: EIP-712 typed-data hash for a claim against `_identity` on the
     *         calling issuer's domain. Signers compute this off-chain to know what to sign.
     * @param _identity Subject identity the claim is about.
     * @param _topic Topic of the claim.
     * @param _data Typed claim envelope to include in the digest.
     * @return The EIP-712 typed-data hash signers should sign.
     */
    function getClaimHash(address _identity, uint256 _topic, Structs.ClaimData memory _data)
        external
        view
        returns (bytes32)
    {
        return _getClaimDigest(msg.sender, _identity, _topic, _data);
    }

    /**
     * @notice Verify a claim then write it to the target identity via its `addClaim`. The target
     *         must have the calling issuer added as a CLAIM_SIGNER key.
     * @param _topic Topic of the claim.
     * @param _scheme Signature scheme used by the issuer (1 = ECDSA).
     * @param _signature Issuer signature over the EIP-712 claim digest.
     * @param _data Typed claim envelope that was signed.
     * @param _uri Optional off-chain URI with the claim contents.
     * @param _identity Target identity that will store the claim.
     */
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

        // Validate against the calling issuer's state directly (no extra round trip through the target).
        require(
            _getClaimStatus(account, _identity, _topic, _signature, _data) == IClaimIssuer.ClaimStatus.Valid,
            Errors.InvalidClaim()
        );

        // Forward to the target identity, which routes addClaim into its own ClaimsModule via fallback.
        _identity.addClaim(_topic, _scheme, account, _signature, _data, _uri);
        emit ClaimAddedTo(address(_identity), _topic, _signature, _data);
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /**
     * @dev Build the EIP-712 claim digest using the calling identity's domain.
     *      The domain is read via IERC5267 from the issuer identity, so off-chain signers
     *      sign against the issuer address (not against this module address).
     * @param account Issuer identity whose EIP-712 domain is queried.
     * @param subject Subject identity the claim is about.
     * @param topic Claim topic.
     * @param data Typed claim envelope.
     * @return The EIP-712 typed-data hash.
     */
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

        // Hash the nested `ClaimData` first, then the outer `Claim` struct, per EIP-712.
        bytes32 dataHash =
            keccak256(abi.encode(_CLAIM_DATA_TYPEHASH, data.issuedAt, data.validUntil, keccak256(data.payload)));
        bytes32 structHash = keccak256(abi.encode(_CLAIM_TYPEHASH, topic, subject, dataHash));
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /**
     * @dev Compute the detailed validity status for a claim. Checks are ordered cheapest first.
     *
     *      1. Time bounds (`issuedAt` set, not in the future, not past `validUntil`).
     *      2. Revoked-digest check (issuer-side revoke or holder-side removal).
     *      3. Signature shape (`abi.encode(bytes signer, bytes rawSig)` with `signer.length >= 20`).
     *      4. Signer purpose (CLAIM_SIGNER on the issuer identity).
     *      5. Cryptographic verification against the EIP-712 digest.
     *
     *      A signature length < 64 bytes can't possibly be a valid ABI-encoded `(bytes, bytes)`
     *      payload (head = 64 bytes minimum), so we short-circuit before calling `abi.decode`
     *      to keep this view crash-safe on garbage input.
     *
     * @param account Issuer identity (holds the revoked set + the CLAIM_SIGNER keys).
     * @param _identity Subject identity the claim is about.
     * @param topic Claim topic.
     * @param sig `abi.encode(bytes signer, bytes rawSig)`. `signer` follows ERC-7913.
     * @param data Typed claim envelope that was signed.
     */
    function _getClaimStatus(
        address account,
        IIdentity _identity,
        uint256 topic,
        bytes memory sig,
        Structs.ClaimData memory data
    ) internal view virtual returns (IClaimIssuer.ClaimStatus) {
        // 1. Time bounds. `issuedAt == 0` is rejected: no real claim is from epoch zero.
        if (data.issuedAt == 0) return IClaimIssuer.ClaimStatus.BadSignature;
        if (block.timestamp < data.issuedAt) return IClaimIssuer.ClaimStatus.NotYetValid;
        // `validUntil == 0` means "no expiry".
        if (data.validUntil != 0 && block.timestamp > data.validUntil) return IClaimIssuer.ClaimStatus.Expired;

        // 2. Revoked-digest. Same mapping for issuer revocations and holder removals.
        bytes32 digest = _getClaimDigest(account, address(_identity), topic, data);
        if (_state[account].revokedDigests[digest]) return IClaimIssuer.ClaimStatus.Revoked;

        // 3. Signature shape. Guard length to avoid `abi.decode` reverting on garbage.
        if (sig.length < 64) return IClaimIssuer.ClaimStatus.BadSignature;
        (bytes memory signer, bytes memory rawSig) = abi.decode(sig, (bytes, bytes));
        if (signer.length < 20) return IClaimIssuer.ClaimStatus.BadSignature;

        // 4. Signer must hold CLAIM_SIGNER on the issuer identity.
        if (!IERC734(account).keyHasPurpose(keccak256(signer), KeyPurposes.CLAIM_SIGNER)) {
            return IClaimIssuer.ClaimStatus.NotIssued;
        }

        // 5. Verify the signature (EOA / 1271 / 7913 verifier, picked by signer length).
        if (!SignatureChecker.isValidSignatureNow(signer, digest, rawSig)) {
            return IClaimIssuer.ClaimStatus.BadSignature;
        }

        return IClaimIssuer.ClaimStatus.Valid;
    }

    /**
     * @dev Require the off-chain caller to hold a claim key on `account`.
     * @param account Identity whose keys are checked.
     * @param caller Off-chain caller, read from the ERC-2771 calldata tail.
     * @param onlyClaimSigner If true, accept CLAIM_SIGNER only (used by `removeClaim`).
     *        If false, accept CLAIM_SIGNER or CLAIM_ADDER (used by `addClaim`).
     */
    function _requireClaimKey(address account, address caller, bool onlyClaimSigner) internal view {
        bytes32 keyHash = keccak256(abi.encodePacked(caller));

        // CLAIM_SIGNER is always enough; it covers both add and remove.
        if (IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_SIGNER)) {
            return;
        }
        // CLAIM_ADDER is only accepted by callers that allow it (addClaim, not removeClaim).
        if (!onlyClaimSigner && IERC734(account).keyHasPurpose(keyHash, KeyPurposes.CLAIM_ADDER)) return;

        revert Errors.SenderDoesNotHaveClaimSignerKey();
    }

    /**
     * @dev Require the off-chain caller to hold MANAGEMENT on `account`.
     * @param account Identity whose keys are checked.
     * @param caller Off-chain caller, read from the ERC-2771 calldata tail.
     */
    function _requireManagement(address account, address caller) internal view {
        require(
            IERC734(account).keyHasPurpose(keccak256(abi.encodePacked(caller)), KeyPurposes.MANAGEMENT),
            Errors.SenderDoesNotHaveManagementKey()
        );
    }

    /**
     * @dev When called through the identity's ERC-7579 fallback, `msg.sender` is the identity.
     *      The real caller is appended as the last 20 bytes per ERC-2771. When called directly,
     *      the tail is attacker-controlled, but the SmartAccount per-target rule prevents
     *      non-MANAGEMENT keys from targeting installed modules as direct call destinations.
     */
    function _msgSender() internal view returns (address sender) {
        if (msg.data.length >= 20) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

}
