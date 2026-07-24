// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import {
    ERC7579SocialRecoveryExecutor
} from "@openzeppelin/accounts/modules/executors/ERC7579SocialRecoveryExecutor.sol";

/// @title RecoveryModule
/// @notice Social recovery for ONCHAINID identities. Wraps OZ's
///         {ERC7579SocialRecoveryExecutor} (vendored via soldeer from
///         OpenZeppelin/openzeppelin-accounts, commit e4c2a32a). All logic lives
///         upstream, we add nothing.
///
/// @dev    Why a wrapper file when there is no body.
///         The upstream contract is marked `abstract`, so we can't deploy it
///         directly. Inheriting it once gives us a concrete contract we can
///         instantiate with `new RecoveryModule()`, a stable name to reference
///         from scripts and tests, and a place to override later if we ever need
///         to (we don't today).
///
/// @dev    Why OZ instead of writing our own.
///         The recovery flow holds authority that can replace MANAGEMENT keys, so
///         writing our own means owning the audit. OZ already built the M-of-N +
///         delay + cancel design we want and pointed us at this file. We pin to
///         a commit so an upstream change can't surprise us. The upstream repo
///         is private and not audited yet; bump the pin once OZ tags an audited
///         release.
///
/// @dev    How an account uses it.
///         A MANAGEMENT key holder installs this as an ERC-7579 executor module
///         and registers the module address in {KeyManager} with the MANAGEMENT
///         purpose. That second step is the ONCHAINID-specific bit: without it,
///         {SmartAccount} would reject the self-targeted `addKey` call the
///         module dispatches at execution time. Same pattern KeyApprovalModule
///         uses.
///
///         Install data is OZ's length-prefixed format documented on
///         `ERC7579SocialRecoveryExecutor.onInstall`:
///             [uint16(execLen), execArgs, uint16(msigLen), msigArgs]
///         where:
///             execArgs = abi.encodePacked(uint32 delay, uint32 expiration)
///             msigArgs = abi.encode(bytes[] guardians, uint64 threshold, uint64[] weights)
///
/// @dev    What recovery actually does.
///         `executeRecovery` dispatches whatever ERC-7579 execution the guardians
///         signed. The canonical recovery payload is a self-targeted
///         `addKeyWithData(newKey, MANAGEMENT, ECDSA, ...)`, which installs a
///         fresh MANAGEMENT key on the identity. The integration tests in
///         test/modules/recovery/RecoveryModule.t.sol exercise that round-trip
///         and show the recovered key works the same as the original for every
///         MANAGEMENT-gated operation.
///
/// @dev    Why this works with our Identity.
///         OZ's module scopes signatures to the account's EIP-712 domain by
///         calling `IERC5267(account).eip712Domain()`. {Identity} inherits OZ's
///         {EIP712}, which exposes that interface. Nothing extra to wire.
contract RecoveryModule is ERC7579SocialRecoveryExecutor { }
