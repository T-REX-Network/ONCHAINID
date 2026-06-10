// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @title Errors
/// @notice Library containing all custom errors the protocol may revert with
library Errors {

    /* ----- Generic ----- */

    /// @notice Reverts if the address is zero
    error ZeroAddress();

    /* ----- IdentityFactory ----- */

    /// @notice Reverts if the function is called on the sender address
    error CannotBeCalledOnSenderAddress();

    /// @notice Reverts if the list of keys is empty
    error EmptyListOfKeys();

    /// @notice Reverts if the string is empty
    error EmptyString();

    /// @notice Reverts if the maximum number of wallets per identity is exceeded
    error MaxWalletsPerIdentityExceeded();

    /// @notice Reverts when {createIdentity} is called by an account that does not hold the
    ///         AccessManager role required for the requested identity type.
    /// @param caller the address that attempted to create the identity.
    /// @param identityType the identity type that was requested.
    /// @param requiredRole the AccessManager role id required for that type (0 = admin-only).
    error NotAuthorizedForIdentityType(address caller, uint256 identityType, uint64 requiredRole);

    /// @notice Reverts if the only linked wallet tries to unlink
    error OnlyLinkedWalletCanUnlink();

    /// @notice Reverts if the token is already linked
    error TokenAlreadyLinked(address token);

    /// @notice Reverts if the wallet is already linked to an identity
    error WalletAlreadyLinkedToIdentity(address wallet);

    /// @notice Reverts if the wallet is also listed in management keys
    error WalletAlsoListedInManagementKeys(address wallet);

    /// @notice Reverts if the wallet is not linked to an identity
    error WalletNotLinkedToIdentity(address wallet);

    /// @notice Reverts if no key with MANAGEMENT purpose is provided
    error NoManagementKeyInKeys();

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
