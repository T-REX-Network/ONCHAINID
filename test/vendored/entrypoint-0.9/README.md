# EntryPoint v0.9 test fixture

Runtime bytecode of the deployed ERC-4337 EntryPoint v0.9. It is injected at the canonical
address with `vm.etch` in `test/aa/PasskeySafeApproval.t.sol`, so user operations are run by the
real EntryPoint and not by a mock.

| File | Contract | Address |
|---|---|---|
| `EntryPoint.bytecode` | `EntryPoint.sol` v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

Source: read from Base Sepolia (chain 84532) on 26 November 2026.
Runtime code hash: `0x216eed2b302d9cb687852c673dfaa962b4c85e2a790f19aa4b61608ea1fee04d`.

The runtime differs from chain to chain in its immutables only (the cached chain id and domain
separator). The contract recomputes the domain separator when the chain id is not the cached one,
so the fixture works on the test chain.

## Refresh

```
cast code 0x433709009B8330FDa32311DF1C2AFA402eD8D009 --rpc-url <base_sepolia_rpc> \
  | sed 's/^0x//' | tr -d '\n' | xxd -r -p > EntryPoint.bytecode
```
