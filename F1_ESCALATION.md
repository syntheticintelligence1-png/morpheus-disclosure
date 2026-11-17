# BuildersV4 F1 — escalation from Medium to High

Target: BuildersV4 proxy 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9 (Base), deposit token MOR
0x7431aDa8a591C955a994a21710752EF9b882b8e3. Fork pinned at Base block 58,680,000.

## The lever that moves it off "temporary DoS = Medium"
`editSubnet` (gated only by `onlySubnetOwner`, a permissionless role: anyone can `createSubnet`
for free, fee=0) sets `withdrawLockPeriodAfterDeposit` with NO upper bound and NO post-deposit
freeze — V4 deleted V3's `editPoolDeadline`. `withdraw` checks
`block.timestamp > userData.lastDeposit + subnet.withdrawLockPeriodAfterDeposit` in checked
uint128. Set the lock to type(uint128).max AFTER deposits and the addition overflows →
Panic(0x11) → withdraw reverts for every staker in that subnet, at every timestamp, forever.
The admin then abandons the subnet. Nothing in BuildersV4/Treasury/owner can lower it except
that subnet's admin. => PERMANENT lock of a bounded-but-material amount of funds (program's
High band), not a recoverable freeze.

## Why it beats the usual rebuttals
- Not an owner/multisig assumption: subnet admin is a permissionless role, not the protocol owner.
- Documented-invariant break: the official Builders FAQ states "users can withdraw their tokens
  at any time." The contract lets an unprivileged party permanently violate that.
- "Victims trusted the subnet" is defeated by chaining with name-squatting: `createSubnet` only
  checks the new id `keccak256(chainid,name)` AND old id `keccak256(name)` are free, so an
  attacker front-runs a known project's name, attracts its would-be stakers, then locks them.

## Honest ceiling
Bounded to the attacker's own subnet TVL (the overflow uses per-subnet lock; cannot touch other
subnets or global TVL). So High, not Critical. Expect possible knock-back to Medium on the
"stakers opted into that admin" argument — lead with permanent-lock + the FAQ invariant.

## PoC (test/BuildersV4Lock.t.sol, forge test -vv)
- test_baseline_withdraw_works: honest 7-day lock -> victim withdraws 100k MOR. Invariant holds.
- test_permanent_lock: attacker raises lock to uint128.max after a 100k MOR deposit; withdraw
  reverts at +10,000 days and +36,500 days. 100,000 MOR (~$69,927 at $0.699275) permanently locked.
No privileged accounts, no owner prank. Both tests pass.

## Fix
Cap `withdrawLockPeriodAfterDeposit <= maxWithdrawLockPeriod` in `_validateSubnet`, and/or forbid
raising the lock in `editSubnet` once a subnet has deposits.
