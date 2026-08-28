# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0]

ONCHAINID v3 is a ground-up re-architecture of the identity stack, developed by T-REX Network in collaboration with OpenZeppelin. The identity is no longer a monolithic ERC-734 / ERC-735 contract: it is an ERC-7579 modular smart account with ERC-4337 account abstraction support, where keys live at the account level and claims, execution rules, signature validation, and recovery are installable modules.

v3 is not storage-compatible or interface-compatible with 2.x. It is a new deployment, not an in-place upgrade of 2.x proxies. The repository is maintained at https://github.com/T-REX-Network/ONCHAINID and published as `@t-rex-network/onchainid`. Licensing remains GPL-3.0; see [LICENSE.md](./LICENSE.md) and [NOTICE.md](./NOTICE.md).

### Breaking changes

- Re-architected `Identity` into three layers: `Identity` (the deployed contract, running a single one-shot setup when its proxy is created), `SmartAccount` (the ERC-7579 modular account, gating module install and removal on the MANAGEMENT purpose and purpose-checking calls from installed executors), and `KeyManager` (a storage-less ERC-734 facade; the canonical key registry lives in the enshrined `ERC734Validator` module).
- ERC-735 claims are no longer implemented inside the identity contract. They are served by the installed `ERC734Validator` module and reached through the account's ERC-7579 fallback handler. Claim calls revert if no module is installed to answer them.
- Externalized the ERC-734 `execute` / `approve` flow into the `KeyApprovalModule` executor, which owns the execution queue, the auto-approval rules, and the execution nonce.
- Extended key purposes: MANAGEMENT (1), ACTION (2), CLAIM_SIGNER (3), ENCRYPTION (4), plus the new CLAIM_ADDER (5) and PROPOSER (6). PROPOSER is a queue-only purpose: it can queue an execution but never runs or approves one on its own.
- Replaced the `ImplementationAuthority` / `IdentityProxy` upgrade pattern with a beacon proxy per identity, deployed through CREATE3 by the factory. A given salt resolves to the same identity address on every chain following the canonical CREATE2 derivation. `initializeBeacon` verifies the derivation at setup and reverts atomically on divergent chains (zkSync Era and similar).
- Replaced `IdFactory` with `IdentityFactory`: identities are typed, each type carries an admin-registered policy (role, self-deployable flag, single-binding flag) and a default module set, and access is controlled through OpenZeppelin `AccessManager`. Two entry points: `createIdentity` (the caller deploys for themselves and is auto-linked as the first wallet) and `createIdentityFor` (role-gated deployment on behalf of another account).
- Rewrote wallet linking. Linked accounts are stored as ERC-7930 interoperable-address envelopes (chain-aware, EVM and non-EVM), linking requires a signature with nonce and expiry (`linkAccount`), accounts can be revoked (`revokeAccount`), and cross-chain links settle through trusted gateways (`settlePendingCrossChainLink`) and trusted verifiers.
- Replaced revert strings with custom errors (`Errors` library).
- Moved storage to ERC-7201 namespaced layouts across upgradeable contracts.
- Migrated the toolchain from Hardhat to Foundry (`forge`), with dependencies managed by soldeer. Solidity 0.8.30, EVM version cancun.
- Renamed the npm package from `@onchain-id/solidity` to `@t-rex-network/onchainid`.
### Added

- ERC-4337 account abstraction: identities validate `UserOperation`s through the installed validator module and can operate with bundlers and paymasters.
- ERC-7913 signers: the userOp signature wire format is `abi.encode(signer, signature)`, where a 20-byte signer is an EOA or ERC-1271 contract and a longer signer is a `verifier || key` blob. Supported key types: ECDSA, RSA, WEBAUTHN (passkeys), MODULE, ACCESS_MANAGER. This enables multi-device signing, including claim signing from passkey devices.
- Per-identity EIP-712 domains, so signatures cannot be replayed against another identity sharing the same module deployment.
- `RecoveryModule`: social recovery for identities, wrapping OpenZeppelin's `ERC7579SocialRecoveryExecutor`. Weighted guardian quorum, delayed execution, cancellable by the account or by a guardian quorum before it runs.
- `EASClaimIssuer`: a stateless `IClaimIssuer` that resolves claims by reading Ethereum Attestation Service attestations live, with an admin-managed topic-to-schema map and per-topic attester allowlists. Revocation, expiry, and wallet unlinking take effect on the next read.
- Claim lifecycle: claims carry `issuedAt` / `validUntil` validity windows, revocation is digest-based, and `getClaimStatus` returns an explicit status (Valid, BadSignature, NotYetValid, Expired, Revoked) instead of a bare boolean.
- Identity types registered at the factory: ASSET (1), INDIVIDUAL (2), CORPORATE (3), IOT (4), CLAIM_ISSUER (5), SMART_CONTRACT (6), PUBLIC_AUTHORITY (7), AI_AGENT (8).
- `ReputationRegistry`: per-identity reputation scores with per-type defaults, writable only through the REPUTATION_MANAGER role via `AccessManager`.
- `IdentityUtilities` (UUPS-upgradeable): an on-chain registry of structured claim-topic schemas (field names and types), with `FormatResolver` for the supported field formats.
- Full Foundry test suite with coverage enforced in CI.
### Removed

- `Gateway`, superseded by the AccessManager-gated factory and the trusted-gateway model for cross-chain links.
- `Verifier` base contract.
- The standalone `ClaimIssuer` implementation. Claim issuers are now regular ONCHAINID identities (type CLAIM_ISSUER) whose `isClaimValid` is served by the claims module, and `EASClaimIssuer` covers EAS-backed issuance. The `IClaimIssuer` interface remains.
- `ImplementationAuthority`, `IdentityProxy`, `Storage`, and `Version` contracts.
- Hardhat and TypeChain tooling.
### Security

- ONCHAINID v3 audited by OpenZeppelin. Report: //TODO: Add Link.

## [2.2.2]

### Updated

- changed solidity version from fixed to flexible (adding ^ before version) to allow using other compilation settings on contracts importing the interfaces

## [2.2.1]

### Changed

- Replaced the storage slot used for ImplementationAuthority on the proxies, to avoid conflict with ERC-1822 on
  block explorers. By using the same storage slot, the explorers were identifying this proxy as an ERC-1822, while
  it's a different implementation here, the storage slot is not used to store the address of the implementation but
  the address to ImplementationAuthority contract that references the implementation

## [2.2.0]

### Added

- Identities are now required to implement the standardized `function isClaimValid(IIdentity _identity, uint256
claimTopic, bytes calldata sig, bytes calldata data) external view returns (bool)`, used for self-attested claims
  (`_identity` is the address of the Identity contract).
- Implemented the `isClaimValid` function in the `Identity` contract.
- IdFactory now implements the `implementationAuthority()` getter.

## [2.1.0]

### Added

- Implemented a new contract `Gateway` to interact with the `IdFactory`. The `Gateway` contract allows individual
  accounts (being EOA or contracts) to deploy identities for their own address as a salt. To deploy using
  a custom salt, a signature from an approved signer is required.
- Implemented a new base contract `Verifier` to be extended by contract requiring identity verification based on claims
  and trusted issuers.

## [2.0.1]

### Added

- added method createIdentityWithManagementKeys() that allows the factory to issue identities with multiple
  management keys.
- tests for the createIdentityWithManagementKeys() method

## [2.0.0]

Version 2.0.0 Audited by Hacken, more details [here](https://tokeny.com/wp-content/uploads/2023/04/Tokeny_ONCHAINID_SC-Audit_Report.pdf)

### Breaking changes

## Deprecation Notice

- ClaimIssuer `revokeClaim` is now deprecated, usage of `revokeClaimBySignature(bytes signature)` is preferred.

### Added

- Add typechain-types (targeting ethers v5).
- Add tests cases for `execute` and `approve` methods.
- Add method `revokeClaimBySignature(bytes signature)` in ClaimIssuer, prefer using this method instead of the now
  deprecated `revokeClaim` method.
- Add checks on ClaimIssuer to prevent revoking an already revoked claim.
- Added Factory for ONCHAINIDs

### Updated

- Switch development tooling to hardhat.
- Implemented tests for hardhat (using fixture for faster testing time).
- Prevent calling `approve` method with a non-request execute nonce (added a require on `executionNone`).
- Update NatSpec of `execute` and `approve` methods.

## [1.4.0] - 2021-01-26

### Updated

- Remove constructor's visibility

## [1.3.0] - 2021-01-21

### Added

- Ownable 0.8.0
- Context 0.8.0

### Updated

- Update version to 1.3.0
- Update contracts to SOL =0.8.0
- Update test to work with truffle
- Update truffle-config.js
- Update solhint config

## [1.2.0] - 2020-11-27

### Added

- Custom Upgradable Proxy contract that behaves similarly to the [EIP-1822](https://eips.ethereum.org/EIPS/eip-1822): Universal Upgradeable Proxy Standard (UUPS), except that it points to an Authority contract which in itself points to an implementation (which can be updated).
- New ImplementationAuthority contract that acts as an authority for proxy contracts
- Library Lock contract to ensure no one can manipulate the Logic Contract once it is deployed
- Version contract that gives the versioning information of the implementation contract

### Moved

- variables in a separate contract (Storage.sol)
- structs in a separate contract (Structs.sol)

### Updated

- Update contracts to SOL =0.6.9

## [1.1.2] - 2020-09-30

### Fixed

- Add Constructor on ClaimIssuer Contract

## [1.1.1] - 2020-09-22

### Fixed

- Fix CI

## [1.1.0] - 2020-09-16

### Added

- ONCHAINID contract uses Proxy based on [EIP-1167](https://eips.ethereum.org/EIPS/eip-1167).
- New contracts,CloneFactory and IdentityFactory
- Github workflows actions
- Build script
- Lint rules for both Solidity and JS
- Ganache-Cli
- Rules for eslint (eslintrc)
- Rules for solhint
- new Tests for Proxy behavior

### Changed

- Replaced Constructor by "Set" function on ERC734
- "Set" function is callable only once on ERC734
- Replaced Yarn by Npm
- Replaced coverage script by coverage plugin
- old Tests for compatibility with new proxy
