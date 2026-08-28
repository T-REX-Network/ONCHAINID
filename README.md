## ![ONCHAINID Smart Contracts](./onchainid_logo_final.png)

![GitHub](https://img.shields.io/github/license/T-REX-Network/ONCHAINID?color=green)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/T-REX-Network/ONCHAINID)
![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/T-REX-Network/ONCHAINID/publish-release.yml)
![GitHub repo size](https://img.shields.io/github/repo-size/T-REX-Network/ONCHAINID)
![GitHub Release Date](https://img.shields.io/github/release-date/T-REX-Network/ONCHAINID)

---

# ONCHAINID Smart Contracts

Digital identities for the T-REX ecosystem. ONCHAINID implements the ERC-734 (key holder) and ERC-735 (claim holder) standards, rebuilt on top of a modular ERC-7579 account with ERC-4337 support.

ONCHAINID v3 was designed and built by [T-REX Network](https://www.trex.network) in collaboration with [OpenZeppelin](https://www.openzeppelin.com).

Learn more about ONCHAINID and the T-REX Network on the official website: [https://www.trex.network](https://www.trex.network).

## What is an ONCHAINID identity?

An identity is a smart contract that belongs to a person, a company, an asset, or any other subject. It does two things:

- **Holds keys (ERC-734).** Keys are addresses granted specific purposes, such as managing the identity or signing claims.
- **Holds claims (ERC-735).** Claims are signed statements about the identity, for example "this identity passed KYC", issued by trusted parties.

Each identity is a modular account. Extra behaviour — claims, execution rules, signature checks, social recovery — is added through installable modules, so the core stays small and each feature can be reviewed on its own.

## Architecture

The identity is built in layers. Each layer has one job:

- **`Identity`** — the concrete contract that gets deployed. It wires the pieces below together and runs a single, one-shot setup step when the proxy is created.
- **`SmartAccount`** — the ERC-7579 modular account. It gates module install and removal on the key registry's `MANAGEMENT` purpose and purpose-checks calls coming from installed executors; user operations are authorized by the installed validator, which the account trusts to scope its own signers.
- **`KeyManager`** — the ERC-734 key registry. It is the single source of truth for which key holds which purpose. Every other part of the system reads keys from here.

Claims (ERC-735) are **not** built into `Identity`. They are served by an installed module (`ERC734Validator`) and reached through the account's fallback handler. If no module is installed to answer them, calling a claim function reverts.

### Key purposes

Each key can hold one or more purposes:

| Purpose         | Value | What it can do                                              |
| --------------- | ----- | ---------------------------------------------------------- |
| `MANAGEMENT`    | 1     | Manage the identity: keys, modules, and top-level settings |
| `ACTION`        | 2     | Execute approved actions on behalf of the identity         |
| `CLAIM_SIGNER`  | 3     | Sign claims for the identity                               |
| `ENCRYPTION`    | 4     | Hold encryption material                                   |
| `CLAIM_ADDER`   | 5     | Add claims to the identity                                 |
| `PROPOSER`      | 6     | Queue an execution, but not run or approve it on its own   |

### Identity types

The factory tags every identity with a type: `ASSET` (1), `INDIVIDUAL` (2), `CORPORATE` (3), `IOT` (4), `CLAIM_ISSUER` (5), `SMART_CONTRACT` (6), `PUBLIC_AUTHORITY` (7), `AI_AGENT` (8).

## Modules

Modules follow the ERC-7579 standard and are installed per identity:

- **`ERC734Validator`** — validates user-operation signatures against the key registry, and serves the ERC-735 claim calls reached through the account fallback.
- **`ERC7579Validator`** — signature validator used to verify user operations.
- **`KeyApprovalModule`** — an executor that owns the execution queue, auto-approval rules, and execution nonce. Queueing requires the `PROPOSER` purpose.
- **`RecoveryModule`** — social recovery for an identity (see notes below).
- **`EASClaimIssuer`** — a stateless claim issuer that reads [EAS](https://attest.org) attestations live (see notes below).

## Factory and cross-chain addresses

`IdentityFactory` deploys each identity as a beacon proxy using `CREATE3`. Because of `CREATE3`, a given `(salt, wallet)` resolves to the **same identity address on every chain** — as long as the factory itself sits at the same address on each chain.

This relies on the standard EVM `CREATE2` derivation `keccak256(0xff, sender, salt, keccak256(initCode))`. Chains that deviate from this derivation produce different addresses. The most common case is **zkSync Era** (and other non-EVM-equivalent zkEVMs), which uses a different prefix byte and hashes bytecode and constructor inputs differently. Since `CREATE3` is built on `CREATE2`, this difference cascades: identities on zkSync will not match addresses on standard EVM chains, no matter which `CREATE3` implementation is used.

**Supported chains:** the stack targets chains that follow the canonical `CREATE2` derivation. The factory enforces this at setup: `initializeBeacon` compares the address `CREATE3` actually deployed the beacon to against the address committed in the factory's constructor, and reverts with `BeaconAddressMismatch` if they differ. On a divergent chain (zkSync Era and similar) initialization therefore fails atomically instead of leaving a factory whose beacon lives at an address it can never reach.

The factory offers two entry points:

- **`createIdentity`** — the caller deploys an identity for themselves and is linked as the first wallet.
- **`createIdentityFor`** — the caller deploys an identity for another account (a token, a vault, and so on). This requires the right role for that identity type.

Each identity type must be registered by an admin before it can be used, and access is controlled with OpenZeppelin's `AccessManager`.

## Recovery module integration notes

`RecoveryModule` adds social recovery to an identity. It is a thin wrapper around OpenZeppelin's `ERC7579SocialRecoveryExecutor`, pulled in from the private `openzeppelin-accounts` repository via soldeer. All recovery logic lives upstream; the wrapper only turns the upstream `abstract` contract into a deployable one.

- **Guardians recover the identity, not a password.** A set of guardians can, together, restore access by meeting a threshold. Recovery is weighted and quorum-based.
- **Recovery is delayed and can be cancelled.** A scheduled recovery only executes after a delay window, and it can be cancelled either by the account itself or by a guardian quorum before it runs.
- **Signatures are scoped to one identity.** Each recovery request is signed against that identity's EIP-712 domain, so signatures cannot be replayed against a different identity that uses the same module.

> Because it depends on the private `openzeppelin-accounts` repository, building this repo requires read access to that repository (see below).

## EAS adapter integration notes

`EASClaimIssuer` is a stateless `IClaimIssuer` that resolves claims by reading [EAS](https://attest.org) attestations live. Integrators — token issuers, compliance officers, and front-end developers — should be aware of three behaviors that are intentional design decisions, not bugs:

- **A factory-revoked wallet does not invalidate identity-level claims.** The adapter accepts an attestation whose recipient is the identity itself or any wallet *ever* linked to it, regardless of the wallet's current factory status. Rationale: if a holder revokes a compromised wallet, their identity-level KYC must not freeze with it — otherwise wallet recovery would deadlock the identity (`isVerified` would fail during the recovery itself). Audit trails will therefore legitimately show "identity KYC valid" alongside a revoked wallet link.
- **The enforcement boundary for a compromised wallet is the token-transfer layer, not the claim layer.** The revoked wallet is blocked where it acts (token transfers, factory operations); the identity's eligibility is a fact about the identity, not about any single wallet. Attestation-level kills happen on EAS (attester revokes) or on the identity (`removeClaim`).
- **`getAttestationData` is a raw read.** It returns the attestation payload even if the attestation is revoked, expired, or from an untrusted attester. Any eligibility or display decision (KYC badges, investment gating) must go through `isClaimValid` / `getClaimStatus` — decoding the payload alone can show stale data for attestations revoked on EAS.

## Getting started

This is a [Foundry](https://book.getfoundry.sh) project. Solidity `0.8.30`, EVM version `cancun`, optimizer on (200 runs). Dependencies are managed with [soldeer](https://soldeer.xyz), listed in `foundry.toml` and locked in `soldeer.lock`.

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`)
- Node.js and npm (used only for git hooks and to run `forge soldeer install`)
- Read access to the private `openzeppelin-accounts` repository. `forge soldeer install` clones it, so git must be authenticated. In CI this is done with a repository secret; locally your normal GitHub git credentials are enough.

### Install

```bash
npm ci                 # installs git hooks and runs `forge soldeer install`
# or, without the hooks:
forge soldeer install  # fetch dependencies only
```

### Build

```bash
npm run build          # forge build
```

### Test

```bash
npm test               # forge test
forge test -vvv        # with stack traces on revert (matches CI)
forge test --match-test <name>          # run a single test
forge test --match-contract <Contract>  # run all tests in one file
```

### Lint and format

```bash
npm run lint           # forge fmt --check (this is what CI runs)
npm run lint:fix       # forge fmt (auto-fix)
```

### Coverage and docs

```bash
npm run coverage       # forge coverage
npm run docs           # forge doc --serve --open
```

## Using the published package

Install the package to use the contracts and interfaces in your own project:

```bash
npm add @t-rex-network/onchainid
```

In Solidity, import the contracts or interfaces directly:

```solidity
import { IIdentity } from "@t-rex-network/onchainid/contracts/interface/IIdentity.sol";
import { IClaimIssuer } from "@t-rex-network/onchainid/contracts/interface/IClaimIssuer.sol";
```

Compiled artifacts (ABI and bytecode) are shipped in the `out/` directory of the package, one JSON file per contract, for example `out/Identity.sol/Identity.json`.

## Versioning and provenance

This repository hosts ONCHAINID **v3**, a ground-up re-architecture of the identity stack. See [CHANGELOG.md](./CHANGELOG.md) for the full release notes.

v3 originated as a fork of the ONCHAINID reference implementation by the [onchain-id project](https://github.com/onchain-id/solidity) (GPL-3.0) and has been substantially rewritten and re-architected. It is not storage-compatible or interface-compatible with the 2.x line: moving from 2.x means a new deployment, not an upgrade of existing proxies. The 2.x implementation remains available in the upstream repository.

## Security and audits

<!-- TODO: link the OpenZeppelin audit report for ONCHAINID v3 when published -->
ONCHAINID v3 is being audited by OpenZeppelin. The audit report will be linked here once published.

Please report security vulnerabilities responsibly to security@trex.network rather than opening a public issue.

## License

Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network").

This project is licensed under the GNU General Public License v3.0. See [LICENSE.md](./LICENSE.md) for the full license text and [NOTICE.md](./NOTICE.md) for copyright, provenance, and trademark information.
