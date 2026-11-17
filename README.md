# Morpheus Builders V4 — permanent withdrawal lock + ongoing reward capture (F1)

Mainnet-fork PoC for a High-severity finding in the deployed **BuildersV4** contract
on Base. A permissionless subnet admin can raise `withdrawLockPeriodAfterDeposit`
to `type(uint128).max` **after** stakers deposit, permanently reverting every
`withdraw()` for that subnet, then keep harvesting those stakers' emission share via
a retained `claimAdmin`.

Full writeup (TARGET / INVARIANT / IMPACT / PRECONDITIONS / ATTACK / POC / FIX),
with the complete PoC source and byte-for-byte `forge` output embedded, is in
[`REPORT.md`](./REPORT.md).

## Scope / target (deployed, Appendix A)

| Contract | Address (Base, chainid 8453) |
|---|---|
| BuildersV4 proxy | `0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9` |
| BuildersTreasuryV2 proxy | `0x9eba628581896ce086cb8f1A513ea6097A8FC561` |
| MOR | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` |

## Reproduce

Pinned Base fork @ block **58,680,000**. No privileged accounts, no `vm.prank`.
The attacker starts with ETH only and buys MOR through the live Uniswap V3 pool.

```bash
# forge-std is vendored in lib/ — no `forge install` needed
forge test -vvvv
```

Expected: 2 passing.
- `test_baseline_honest_withdraw` — honest 7-day lock, withdraw succeeds (invariant holds)
- `test_live_inducible_full_attack` — 300,000 MOR ($209,782) trapped; attacker's
  `claimAdmin` harvests 27,056 MOR ($18,919) in 120 days while victims stay locked

The exact captured runs are in [`forge_output_full.txt`](./forge_output_full.txt)
(full traces) and [`forge_output.txt`](./forge_output.txt).
