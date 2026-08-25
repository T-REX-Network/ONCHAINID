## ![OnchainID Smart Contracts](./onchainid_logo_final.png)

![GitHub](https://img.shields.io/github/license/onchain-id/solidity?color=green)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/onchain-id/solidity)
![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/onchain-id/solidity/publish-release.yml)
![GitHub repo size](https://img.shields.io/github/repo-size/onchain-id/solidity)
![GitHub Release Date](https://img.shields.io/github/release-date/onchain-id/solidity)

---

# OnchainID Smart Contracts

Smart contracts for secure blockchain identities. OnchainID implements the ERC-734 (key holder) and ERC-735 (claim holder) standards, rebuilt on top of a modular ERC-7579 account with ERC-4337 support.

Learn more about OnchainID and blockchain identities on the official website: [https://onchainid.com](https://onchainid.com).

## What is an OnchainID identity?

An identity is a smart contract that belongs to a person, a company, an asset, or any other subject. It does two things:

- **Holds keys (ERC-734).** Keys are addresses granted specific purposes, such as managing the identity or signing claims.
- **Holds claims (ERC-735).** Claims are signed statements about the identity, for example "this identity passed KYC", issued by trusted parties.

Each identity is a modular account. Extra behaviour — claims, execution rules, signature checks, social recovery — is added through installable modules, so the core stays small and each feature can be reviewed on its own.

## Architecture

The identity is built in layers. Each layer has one job:

- **`Identity`** — the concrete contract that gets deployed. It wires the pieces below together and runs a single, one-shot setup step when the proxy is created.
- **`SmartAccount`** — the ERC-7579 modular account. It decides who is allowed to run transactions and install or remove modules, using the key registry for authorization.
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
npm add @onchain-id/solidity
```

```javascript
// contracts, if you need to deploy them
const {
  contracts: { ERC734, Identity },
} = require("@onchain-id/solidity");

// interfaces, if you need to interact with deployed contracts
const {
  interfaces: { IERC734, IERC735 },
} = require("@onchain-id/solidity");
```

Each artifact exposes its ABI and bytecode, for example `ERC734.abi` and `ERC734.bytecode`.

## License

Released under the GPL-3.0 license. See [LICENSE.md](./LICENSE.md).

---

<div style="padding: 16px;">
   <a href="https://tokeny.com/wp-content/uploads/2023/04/Tokeny_ONCHAINID_SC-Audit_Report.pdf" target="_blank">
       <img src="https://hacken.io/wp-content/uploads/2023/02/ColorWBTypeSmartContractAuditBackFilled.png" alt="Proofed by Hacken - Smart contract audit" style="width: 258px; height: 100px;">
   </a>
</div>
