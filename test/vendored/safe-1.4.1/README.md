# Safe v1.4.1 test fixtures

Creation (init) code of the Safe v1.4.1 contracts. `test/aa/PasskeySafeApproval.t.sol` deploys
them with `create`, so the test runs against the real Safe and not a mock.

| File | Contract | Init code hash |
|---|---|---|
| `Safe.bytecode` | `Safe.sol` (singleton) | `0xbdd9e3833a8bdf0f6b4312e07bc851afc298d53690a00a28cade5de8b6ac0f36` |
| `SafeProxyFactory.bytecode` | `SafeProxyFactory.sol` | `0x596f87ec561ad5ea1c13253af5c91247a713253499b74a5d594537cae42eaaa9` |

Source: the same files the T-REX deployment tooling uses (`deploy/vendor/safe-1.4.1/*.hex` in
T-REX-Network/T-REX), stored here as raw binary. The hashes are the ones recorded in that
repository's `deploy/vendor/vendor.json`.

## Check

```
cast keccak 0x$(xxd -p Safe.bytecode | tr -d '\n')
```
