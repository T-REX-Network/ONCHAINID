// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {
    IERC7579Module,
    IERC7579ModuleConfig,
    IERC7579Validator,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
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
 * @notice ERC-735 claims plus issuer functions (revoke, addClaimTo, isClaimValid). Installed on
 *         an Identity as an ERC-7579 fallback so calls to these selectors on the identity land here.
 *
 * @dev    Storage is keyed by the calling identity (`msg.sender`), so one deployment serves every
 *         identity that installs it. EIP-712 digests are built from the calling identity's domain
 *         (read via IERC5267), so off-chain signers still sign against the identity address.
 */
contract ClaimsModule is IERC7579Module, IERC735 {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev Per-identity claim state. Indexed by the calling account (Identity).
    struct AccountState {
        mapping(bytes32 => Structs.Claim) claims;
        mapping(uint256 => EnumerableSet.Bytes32Set) claimsByTopic;
        mapping(bytes => bool) revokedClaims;
    }

    /// @dev Storage shared across all identities that install this module.
    mapping(address => AccountState) private _state;

    /// @dev EIP-712 typehash: Claim(address identity,uint256 topic,bytes data).
    bytes32 internal constant _CLAIM_TYPEHASH = keccak256("Claim(address identity,uint256 topic,bytes data)");

    /// @notice Emitted when an issuer revokes one of its own claim signatures.
    event ClaimRevoked(bytes indexed signature);

    /// @notice Emitted when `addClaimTo` adds a claim to another identity.
    event ClaimAddedTo(address indexed identity, uint256 topic, bytes signature, bytes data);

    // -----------------------------------------------------------------------
    // ERC-7579 module metadata
    // -----------------------------------------------------------------------

    /**
     * @inheritdoc IERC7579Module
     * @param moduleTypeId The ERC-7579 module type to query.
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
     * @dev No-op. Existing claim/revocation state on the uninstalling account is left in place.
     */
    function onUninstall(bytes calldata) external pure { }

    // -----------------------------------------------------------------------
    // ERC-735 ABI, reached through the identity's fallback handler
    // -----------------------------------------------------------------------

    /**
     * @inheritdoc IERC735
     * @param _topic Topic of the claim (see {ClaimTopics}).
     * @param _scheme Signature scheme used by the issuer (1 = ECDSA).
     * @param _issuer Address of the issuer that signed the claim. May be the calling identity itself.
     * @param _signature Issuer's signature over the EIP-712 claim digest.
     * @param _data Claim payload that the signature signs over.
     * @param _uri Optional off-chain URI with the claim contents.
     * @return claimRequestId `keccak256(abi.encode(_issuer, _topic))`. Also serves as the storage key.
     */
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes memory _signature,
        bytes memory _data,
        string memory _uri
    ) public override returns (bytes32 claimRequestId) {
        // When reached via fallback, msg.sender is the Identity and _msgSender() is the off-chain caller.
        address account = msg.sender;
        // CLAIM_SIGNER or CLAIM_ADDER can add a claim.
        _requireClaimKey(
            account,
            _msgSender(),
            /* onlyClaimSigner */
            false
        );

        // For claims from another issuer, ask that issuer to confirm. Skip the extra call if the issuer is this identity.
        if (_issuer != account) {
            require(
                IClaimIssuer(_issuer).isClaimValid(IIdentity(account), _topic, _signature, _data), Errors.InvalidClaim()
            );
        }

        // (issuer, topic) is the claim id. Adding the same id again overwrites the previous entry.
        AccountState storage s = _state[account];
        bytes32 claimId = keccak256(abi.encode(_issuer, _topic));
        s.claims[claimId] = Structs.Claim({
            topic: _topic, scheme: _scheme, issuer: _issuer, signature: _signature, data: _data, uri: _uri
        });

        // EnumerableSet.add returns true on first insertion (emit ClaimAdded); false means it's an update (emit ClaimChanged).
        if (s.claimsByTopic[_topic].add(claimId)) {
            emit ClaimAdded(claimId, _topic, _scheme, _issuer, _signature, _data, _uri);
        } else {
            emit ClaimChanged(claimId, _topic, _scheme, _issuer, _signature, _data, _uri);
        }

        return claimId;
    }

    /**
     * @inheritdoc IERC735
     * @param _claimId Storage key returned by {addClaim}.
     * @return success True when the claim was found and removed.
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

        // Drop the topic index entry first so we still have the claim fields available for the event.
        s.claimsByTopic[topic].remove(_claimId);
        emit ClaimRemoved(_claimId, topic, c.scheme, c.issuer, c.signature, c.data, c.uri);
        delete s.claims[_claimId];

        return true;
    }

    /**
     * @inheritdoc IERC735
     * @param _claimId Storage key returned by {addClaim}.
     * @return topic Claim topic.
     * @return scheme Signature scheme used by the issuer.
     * @return issuer Address that signed the claim.
     * @return signature Issuer signature over the EIP-712 claim digest.
     * @return data Claim payload.
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
            bytes memory data,
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

    // -----------------------------------------------------------------------
    // ClaimIssuer extras
    // -----------------------------------------------------------------------

    /**
     * @notice Mark a signature as revoked. Caller is the issuer identity reached via fallback.
     * @param signature Issuer signature to revoke. Future {isClaimValid} checks against this signature return false.
     */
    function revokeClaimBySignature(bytes calldata signature) external {
        // Only a MANAGEMENT key can revoke. Once revoked, every claim that uses this signature is rejected.
        address account = msg.sender;
        _requireManagement(account, _msgSender());
        // Revoking twice would emit a confusing event. Fail with a clear error instead.
        require(!_state[account].revokedClaims[signature], Errors.ClaimAlreadyRevoked());

        _state[account].revokedClaims[signature] = true;
        emit ClaimRevoked(signature);
    }

    /**
     * @notice Revoke a claim issued by this identity on a target identity. Pulls the claim from
     *         the target (which routes back into this module's `_state[target]`), checks
     *         issuership, and marks the signature revoked in this issuer's `_state`.
     * @param _claimId Storage key of the claim on the target identity.
     * @param _identity Target identity holding the claim.
     * @return True on successful revocation.
     */
    function revokeClaim(bytes32 _claimId, address _identity) external returns (bool) {
        address account = msg.sender;
        _requireManagement(account, _msgSender());

        // Pull the claim from the target. This routes through that identity's fallback into its own _state.
        (,, address issuer, bytes memory sig,,) = IIdentity(_identity).getClaim(_claimId);
        // Cannot revoke a claim that wasn't issued by this identity.
        require(issuer == account, Errors.NotOwnIssuance());
        require(!_state[account].revokedClaims[sig], Errors.ClaimAlreadyRevoked());

        _state[account].revokedClaims[sig] = true;
        emit ClaimRevoked(sig);
        return true;
    }

    /**
     * @notice True if `signature` has been revoked by the calling issuer (msg.sender).
     * @param _sig Signature to look up in the calling issuer's revocation set.
     * @return True when the signature has been revoked.
     */
    function isClaimRevoked(bytes memory _sig) public view returns (bool) {
        return _state[msg.sender].revokedClaims[_sig];
    }

    /**
     * @notice Verify a claim against the identity. Wraps the signature check with a revocation
     *         lookup against the *issuer* identity (the address the off-chain signer signed as).
     * @dev    The `_identity` parameter is the **subject** the claim is about. The signature
     *         is verified against the calling identity (`msg.sender`), which is the issuer
     *         routing this call through its fallback. We then check that the issuer hasn't
     *         revoked this signature.
     * @param _identity Subject identity the claim is about.
     * @param claimTopic Topic of the claim.
     * @param sig Signature produced by a CLAIM_SIGNER key of the issuer.
     * @param data Claim payload that was signed.
     * @return True when the signature is not revoked and the issuer's ERC-1271 check accepts it.
     */
    function isClaimValid(IIdentity _identity, uint256 claimTopic, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool)
    {
        return _isClaimValid(msg.sender, _identity, claimTopic, sig, data);
    }

    /**
     * @notice Off-chain helper: EIP-712 typed-data hash for a claim against `_identity` on the
     *         calling issuer's domain.
     * @param _identity Subject identity the claim is about.
     * @param _topic Topic of the claim.
     * @param _data Claim payload to include in the digest.
     * @return The EIP-712 typed-data hash signers should sign.
     */
    function getClaimHash(address _identity, uint256 _topic, bytes memory _data) external view returns (bytes32) {
        return _claimDigest(msg.sender, _identity, _topic, _data);
    }

    /**
     * @notice Verify a claim then write it to the target identity via its `addClaim`. The target
     *         identity must have the calling issuer added as a CLAIM_SIGNER key.
     * @param _topic Topic of the claim.
     * @param _scheme Signature scheme used by the issuer (1 = ECDSA).
     * @param _signature Issuer signature over the EIP-712 claim digest.
     * @param _data Claim payload that the signature signs over.
     * @param _uri Optional off-chain URI with the claim contents.
     * @param _identity Target identity that will store the claim.
     */
    function addClaimTo(
        uint256 _topic,
        uint256 _scheme,
        bytes calldata _signature,
        bytes calldata _data,
        string calldata _uri,
        IIdentity _identity
    ) external {
        address account = msg.sender;
        _requireManagement(account, _msgSender());

        // Run the revocation + signature check directly against the issuer's state.
        require(_isClaimValid(account, _identity, _topic, _signature, _data), Errors.InvalidClaim());

        // Forward to the target identity, which will route addClaim into its own ClaimsModule via fallback.
        _identity.addClaim(_topic, _scheme, account, _signature, _data, _uri);
        emit ClaimAddedTo(address(_identity), _topic, _signature, _data);
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /**
     * @dev Build the EIP-712 claim digest using the calling identity's domain.
     * @param account Issuer identity whose EIP-712 domain is queried via IERC5267.
     * @param subject Subject identity the claim is about.
     * @param topic Claim topic.
     * @param data Claim payload.
     * @return The EIP-712 typed-data hash.
     */
    function _claimDigest(address account, address subject, uint256 topic, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        // Read the calling identity's EIP-712 domain so off-chain signers sign against the identity address.
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IERC5267(account).eip712Domain();

        // EIP-712 domain separator built from the issuer identity's domain fields.
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );

        // The subject identity is included inside the struct hash, even though the domain belongs to the issuer.
        bytes32 structHash = keccak256(abi.encode(_CLAIM_TYPEHASH, subject, topic, keccak256(data)));
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /**
     * @dev Revocation lookup, CLAIM_SIGNER purpose check, then ERC-1271 signature verification
     *      against the issuer's installed validator. Shared by `isClaimValid` (external view)
     *      and `addClaimTo` (avoids a self-call).
     *
     *      Why this is not delegated to `IERC1271(account).isValidSignature`: that path is hard
     *      coded to the ACTION purpose (see `SmartAccount.isValidSignature`). Claim signatures
     *      must require CLAIM_SIGNER. We do the purpose check here and then ask the validator
     *      module to do the crypto, so the account stays claim agnostic.
     *
     * @param account Issuer identity to check the revocation set against.
     * @param _identity Subject identity the claim is about.
     * @param topic Claim topic.
     * @param sig Wire format `[validator address (20)][abi.encode(bytes signer, bytes rawSig)]`.
     * @param data Claim payload that was signed.
     * @return True when the signature is not revoked, the signer holds CLAIM_SIGNER on the
     *         issuer, and the validator module accepts the signature.
     */
    function _isClaimValid(address account, IIdentity _identity, uint256 topic, bytes calldata sig, bytes calldata data)
        internal
        view
        returns (bool)
    {
        // Stop early if the issuer already revoked this signature.
        if (_state[account].revokedClaims[sig]) return false;

        // The signature must start with a 20-byte validator address. Anything shorter is invalid.
        if (sig.length < 20) return false;

        // Hash the claim using the issuer's EIP-712 domain, the same one the signer used off-chain.
        bytes32 digest = _claimDigest(account, address(_identity), topic, data);

        // First 20 bytes tell us which installed validator module should check the signature.
        address validator = address(bytes20(sig[:20]));
        // The rest is what we pass to that validator: abi.encode(bytes signer, bytes rawSig).
        bytes calldata moduleSig = sig[20:];

        // The validator must be installed on the issuer; if not, there is nothing to call.
        if (!IERC7579ModuleConfig(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, validator, "")) {
            return false;
        }

        // Inner format is `abi.encode(bytes signer, bytes rawSig)`. keccak256(signer) is the keyHash
        // stored in the issuer's ERC-734 keys.
        (bytes memory signerBytes,) = abi.decode(moduleSig, (bytes, bytes));
        // The signer must hold CLAIM_SIGNER on the issuer; otherwise it cannot sign claims.
        if (!IERC734(account).keyHasPurpose(keccak256(signerBytes), KeyPurposes.CLAIM_SIGNER)) {
            return false;
        }

        // Ask the validator module to check the signature. Wrap in try/catch so a bad module
        // cannot make this view function revert.
        try IERC7579Validator(validator).isValidSignatureWithSender(msg.sender, digest, moduleSig) returns (
            bytes4 magic
        ) {
            return magic == IERC1271.isValidSignature.selector;
        } catch {
            return false;
        }
    }

    /**
     * @dev Require the off-chain caller to hold a claim key on `account`.
     *      Self-calls (account == caller) are always allowed.
     * @param account Identity whose keys are checked.
     * @param caller Off-chain caller, read from the ERC-2771 calldata tail.
     * @param onlyClaimSigner If true, accept CLAIM_SIGNER only (used by {removeClaim}).
     *        If false, accept CLAIM_SIGNER or CLAIM_ADDER (used by {addClaim}).
     */
    function _requireClaimKey(address account, address caller, bool onlyClaimSigner) internal view {
        // When the identity calls itself, skip the key check.
        if (caller == account) return;

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
        if (caller == account) return;
        require(
            IERC734(account).keyHasPurpose(keccak256(abi.encodePacked(caller)), KeyPurposes.MANAGEMENT),
            Errors.SenderDoesNotHaveManagementKey()
        );
    }

    /**
     * @dev When called through the identity's ERC-7579 fallback, `msg.sender` is the identity.
     *      The real caller is tacked onto the end of calldata as the last 20 bytes (per ERC-2771).
     *      Same trick as KeyApprovalModule.
     * @return sender The real caller when reached via fallback, otherwise `msg.sender`.
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
