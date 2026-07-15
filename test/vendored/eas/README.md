# EAS test fixtures

Runtime bytecode of the deployed Ethereum Attestation Service contracts on
Ethereum mainnet. Injected at the canonical mainnet addresses via `vm.etch`
in `EASClaimIssuer.t.sol` so the adapter is tested against the real EAS
bytecode instead of a mock.

## Contents

| File | Contract | Mainnet address |
|---|---|---|
| `EAS.bytecode` | `EAS.sol` | `0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587` |
| `SchemaRegistry.bytecode` | `SchemaRegistry.sol` | `0xA7b39296258348C78294F95B872b282326A97BDF` |

`EAS`'s constructor bakes the SchemaRegistry address into runtime bytecode as
an immutable, so both contracts must be etched at their mainnet addresses for
`EAS._attest` to reach the correct `SchemaRegistry.getSchema`.

## Refresh

Sourced from Sourcify:

```
curl "https://sourcify.dev/server/v2/contract/1/<address>?fields=runtimeBytecode.onchainBytecode" \
  | jq -r '.runtimeBytecode.onchainBytecode' \
  | sed 's/^0x//' | tr -d '\n' > <name>.bytecode
```

The deployed EAS contracts are non-upgradable, so these files rarely need
refreshing.
