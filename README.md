## ![OnchainID Smart Contracts](./onchainid_logo_final.png)

![GitHub](https://img.shields.io/github/license/onchain-id/solidity?color=green)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/onchain-id/solidity)
![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/onchain-id/solidity/publish-release.yml)
![GitHub repo size](https://img.shields.io/github/repo-size/onchain-id/solidity)
![GitHub Release Date](https://img.shields.io/github/release-date/onchain-id/solidity)

---

# OnchainID Smart Contracts

Smart Contracts for secure Blockchain Identities, implementation of the ERC734 and ERC735 proposal standards.

Learn more about OnchainID and Blockchain Identities on the official OnchainID website: [https://onchainid.com](https://onchainid.com).

## Usage

- Install contracts package to use in your repository `yarn add @onchain-id/solidity`
- Require desired contracts in-code (should you need to deploy them):
  ```javascript
  const {
    contracts: { ERC734, Identity },
  } = require("@onchain-id/solidity");
  ```
- Require desired interfaces in-code (should you need to interact with deployed contracts):
  ```javascript
  const {
    interfaces: { IERC734, IERC735 },
  } = require("@onchain-id/solidity");
  ```
- Access contract ABI `ERC734.abi` and ByteCode `ERC734.bytecode`.

## Cross-chain Identity addresses

`IdFactory` deploys Identities through `CREATE3`, so a given `(salt, wallet)` resolves to the same Identity address on every chain — provided `IdFactory` itself lives at the same address on each chain.

This property relies on the canonical EVM `CREATE2` derivation `keccak256(0xff, sender, salt, keccak256(initCode))`. Chains that deviate from this derivation will produce different addresses. The most common case is **zkSync Era** (and other non-EVM-equivalent zkEVMs), which uses a different prefix byte and hashes bytecode and constructor inputs differently. Because `CREATE3` is built on top of `CREATE2`, this divergence cascades: Identities deployed on zkSync (or chains using its stack) will not match addresses on canonical EVM chains, regardless of which `CREATE3` implementation is used.

## EAS adapter integration notes

`EASClaimIssuer` is a stateless `IClaimIssuer` that resolves claims by reading [EAS](https://attest.org) attestations live. Integrators — token issuers, compliance officers, and front-end developers — should be aware of three behaviors that are intentional design decisions, not bugs:

- **A factory-revoked wallet does not invalidate identity-level claims.** The adapter accepts an attestation whose recipient is the identity itself or any wallet *ever* linked to it, regardless of the wallet's current factory status. Rationale: if a holder revokes a compromised wallet, their identity-level KYC must not freeze with it — otherwise wallet recovery would deadlock the identity (`isVerified` would fail during the recovery itself). Audit trails will therefore legitimately show "identity KYC valid" alongside a revoked wallet link.
- **The enforcement boundary for a compromised wallet is the token-transfer layer, not the claim layer.** The revoked wallet is blocked where it acts (token transfers, factory operations); the identity's eligibility is a fact about the identity, not about any single wallet. Attestation-level kills happen on EAS (attester revokes) or on the identity (`removeClaim`).
- **`getAttestationData` is a raw read.** It returns the attestation payload even if the attestation is revoked, expired, or from an untrusted attester. Any eligibility or display decision (KYC badges, investment gating) must go through `isClaimValid` / `getClaimStatus` — decoding the payload alone can show stale data for attestations revoked on EAS.

## Development

- Install dev dependencies `npm ci`
- Update interfaces and contracts code.
- Run lint `npm run lint`
- Compile code `npm run compile`

### Testing

- Run `npm ci`
- Run `npm test`
  - Test will be executed against a local Hardhat network.

---

<div style="padding: 16px;">
   <a href="https://tokeny.com/wp-content/uploads/2023/04/Tokeny_ONCHAINID_SC-Audit_Report.pdf" target="_blank">
       <img src="https://hacken.io/wp-content/uploads/2023/02/ColorWBTypeSmartContractAuditBackFilled.png" alt="Proofed by Hacken - Smart contract audit" style="width: 258px; height: 100px;">
   </a>
</div>
