// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @title Errors
/// @notice Library containing all custom errors the protocol may revert with
library Errors {

    /* ----- Generic ----- */

    /// @notice Reverts if the address is zero
    error ZeroAddress();

    /* ----- IdentityFactory ----- */

    /// @notice Reverts if the list of keys is empty
    error EmptyListOfKeys();

    /// @notice Reverts if the string is empty
    error EmptyString();

    /// @notice Reverts if the token is already linked
    error TokenAlreadyLinked(address token);

    /// @notice Reverts when a caller tries to deploy an identity of a type whose
    ///         configured AM role they do not hold.
    /// @param caller the address that attempted the deployment.
    /// @param identityType the identity type that was requested.
    /// @param requiredRole the AM role id required for that type.
    error NotAuthorizedForIdentityType(address caller, uint256 identityType, uint64 requiredRole);

    /// @notice Reverts when a deploy is attempted for a type the admin has not registered.
    ///         Admin enables a type by calling `setIdentityTypePolicy`. Use the AM's
    ///         `PUBLIC_ROLE` for open types.
    error UnknownIdentityType(uint256 identityType);

    /// @notice Reverts when {createIdentity} is called for a type whose policy has
    ///         `selfDeployable = false`. Self-deploy is gated per type because some
    ///         types (e.g. ASSET, SMART_CONTRACT) represent contracts, not EOAs, so
    ///         the `msg.sender = first wallet` binding does not apply to them. Admin
    ///         opts a type in via {setIdentityTypePolicy}.
    error IdentityTypeNotSelfDeployable(uint256 identityType);

    /// @notice Reverts if no key with MANAGEMENT purpose is provided
    error NoManagementKeyInKeys();

    /// @notice Reverts when an identity is initialized with no validator and no executor
    ///         module. Without either, the account cannot verify signatures or dispatch
    ///         outbound calls.
    error IdentityNoValidatorOrExecutor();

    /// @notice Reverts when a wallet is already linked to a different identity than the one
    ///         currently trying to claim it. Sticky binding: a wallet can be re-linked only to
    ///         its original identity, never to another.
    error WalletBoundToAnotherIdentity(bytes wallet, address boundIdentity);

    /// @notice Reverts when a wallet that was previously revoked is presented to {linkAccount}.
    ///         Revocation is terminal. A wallet cannot be re-linked after being revoked.
    error WalletAlreadyRevoked(bytes wallet);

    /// @notice Reverts when an operation requires the wallet to be in the `Active` lifecycle
    ///         state (e.g. {revokeAccount}) but it is not.
    error WalletNotActive(bytes wallet);

    /// @notice Reverts when {linkAccount} is called by a contract that was not deployed by
    ///         this factory. Only factory-deployed identities can pull wallets in.
    error NotFactoryIdentity(address caller);

    /// @notice Reverts when an EIP-712 link signature is presented after its `expiry`, or
    ///         when `expiry == 0` (callers must set freshness explicitly).
    error ExpiredSignature(uint256 expiry);

    /// @notice Reverts when {linkAccount} is called on an asset identity. An asset
    ///         identity represents one specific token contract. Adding more wallets to
    ///         it would break the 1:1 token↔identity mapping.
    error CannotLinkToAssetIdentity(address identity);

    /// @notice Reverts when {revokeAccount} is called on a non-signing-entity identity
    ///         (ASSET or SMART_CONTRACT). The bound contract cannot sign a fresh
    ///         {linkAccount} digest, so revoking would orphan the factory's discovery
    ///         entry permanently with no recovery path.
    error CannotRevokeFromNonSigningIdentity(address identity);

    /// @notice Reverts when a wallet is already actively linked to the calling identity.
    error WalletAlreadyLinkedToIdentity(bytes wallet);

    /// @notice Reverts when an operation references a wallet that has never been linked, or
    ///         is not currently part of the calling identity's active set.
    error WalletNotLinkedToIdentity(bytes wallet);

    /// @notice Reverts when {confirmCrossChainLink} is called for a wallet that has no
    ///         pending cross-chain proposal. Either the proposal was never made, it
    ///         already confirmed, or it expired and was cleared.
    error NoPendingCrossChainLink(bytes wallet);

    /// @notice Reverts when the caller of {confirmCrossChainLink} is not the identity
    ///         named in the pending proposal. The cross-chain message named one
    ///         identity; only that identity can finalize the link.
    error PendingCrossChainLinkIdentityMismatch(bytes wallet, address pendingIdentity);

    /// @notice Reverts when an inbound cross-chain proposal targets a wallet that
    ///         already has a registry entry (active or revoked). Sticky binding
    ///         applies to the cross-chain path the same way it does to the EVM path.
    error WalletAlreadyHasEntry(bytes wallet);

    /* ----- Verifier ----- */

    /// @notice The claim topic already exists.
    error ClaimTopicAlreadyExists(uint256 claimTopic);

    /// @notice The maximum number of claim topics is exceeded.
    error MaxClaimTopicsExceeded();

    /// @notice The maximum number of trusted issuers is exceeded.
    error MaxTrustedIssuersExceeded();

    /// @notice The trusted issuer already exists.
    error TrustedIssuerAlreadyExists(address trustedIssuer);

    /// @notice The trusted claim topics cannot be empty.
    error TrustedClaimTopicsCannotBeEmpty();

    /// @notice The trusted issuer does not exist.
    error NotATrustedIssuer(address trustedIssuer);

    /* ----- ClaimIssuer ----- */

    /// @notice The claim already exists.
    error ClaimAlreadyRevoked();

    /* ----- Identity ----- */

    /// @notice Interacting with the library contract is forbidden.
    error InteractingWithLibraryContractForbidden();

    /// @notice The sender does not have the management key.
    error SenderDoesNotHaveManagementKey();

    /// @notice The sender does not have the claim signer key.
    error SenderDoesNotHaveClaimSignerKey();

    /// @notice The sender does not have the action key.
    error SenderDoesNotHaveActionKey();

    /// @notice The initial key was already setup.
    error InitialKeyAlreadySetup();

    /// @notice The key is not registered.
    error KeyNotRegistered(bytes32 key);

    /// @notice The key already has the purpose.
    error KeyAlreadyHasPurpose(bytes32 key, uint256 purpose);

    /// @notice The key does not have the purpose.
    error KeyDoesNotHavePurpose(bytes32 key, uint256 purpose);

    /// @notice The claim is not registered.
    error ClaimNotRegistered(bytes32 claimId);

    /// @notice The request is not valid.
    error InvalidRequestId();

    /// @notice The request is already executed.
    error RequestAlreadyExecuted();

    /// @notice The claim is invalid.
    error InvalidClaim();

    /* ----- SmartAccount ----- */

    /// @notice The signature is invalid.
    error InvalidSignature();

    /// @notice The signer data is invalid or too short.
    error InvalidSignerData();

    /// @notice The last MANAGEMENT key cannot be removed (would render the identity unrecoverable).
    error CannotRemoveLastManagementKey();

    /// @notice Reverts when a ClaimIssuer attempts to revoke a claim that was not issued by itself.
    error NotOwnIssuance();

    /// @notice The validator module specified in a UserOp/signature is not installed.
    error ValidatorModuleNotInstalled(address module);

    /// @notice The signer key does not have the required purpose for the requested execution.
    error PurposeNotAuthorizedForCall(bytes32 keyHash, address target);

    /// @notice The execution mode requested is not supported by the account's purpose check.
    error UnsupportedExecutionMode(bytes32 mode);

    /// @notice An installed executor or fallback handler tried to dispatch a call whose target
    ///         is not authorized by the purpose registered for that module at install time.
    ///         Also raised at install time if the module's initData does not begin with a
    ///         non-zero `uint256 purpose`.
    error ExecutorPurposeNotAuthorized();

    /// @notice `KeyApprovalModule.canAutoApprove` was queried for an `account` that does not
    ///         match `msg.sender`. The module only answers about the calling identity's own
    ///         authorization table; cross-identity queries are rejected.
    error UnauthorizedPolicyQuery();

    /// @notice ETH push from `KeyApprovalModule` back to the identity failed.
    error ReturnToAccountFailed();

    /// @notice `addKey` `_type` doesn't match the existing key's stored type.
    error KeyTypeMismatch(bytes32 key, uint256 storedType, uint256 providedType);

    /* ----- IdentityUtilities ----- */

    /// @notice 0 is not a valid topic.
    error EmptyTopic();

    /// @notice 0 is not a valid Format.
    error EmptyFormat();

    /// @notice Name cannot be left empty.
    error EmptyName();

    /// @notice Use update function for existing topics.
    error TopicAlreadyExists(uint256 topic);

    /// @notice Topic is not registered yet.
    error TopicNotFound(uint256 topic);

    /* ----- ClaimIssuerFactory ----- */

    /// @notice The claim issuer already exists.
    error ClaimIssuerAlreadyDeployed(address managementKey);

    /// @notice The address is blacklisted.
    error Blacklisted(address addr);

    /// @notice The call failed.
    error CallFailed();

}
