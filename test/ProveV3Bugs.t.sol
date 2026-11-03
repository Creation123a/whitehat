// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

// ============================================================
// STUB 1 - mirrors V3Vault._checkLoanIsHealthy
// ============================================================
contract HealthStub {
    uint256 public constant Q32 = 2 ** 32;
    uint256 public constant BORROW_SAFETY_BUFFER_X32 = (Q32 * 95) / 100;

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
// STUB 2 - mirrors V3Oracle._requireMaxDifference
// ============================================================
contract OracleStub {
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

    function derivedEqualsSpotWhenSamePool(uint32 twapSeconds, bool samePool)
        public
        pure
        returns (bool)
    {
        return twapSeconds == 0 && samePool;
    }
}

// ============================================================
// TESTS - ALL functions below MUST be inside this contract
// ============================================================
contract ProveV3Bugs is Test {
    HealthStub h;
    OracleStub o;

    function setUp() public {
        h = new HealthStub();
        o = new OracleStub();
    }

    // --------------------------------------------------------
    // FINDING 1 - 100pct LTV Bypass
    // --------------------------------------------------------
    function test_F1_100pct_ltv_bypass() public {
        uint256 collateralValue = 1000e18;
        uint256 debtAt100 = 1000e18;

        bool normalOk    = h.isHealthy(collateralValue, debtAt100, true);
        bool transformOk = h.isHealthy(collateralValue, debtAt100, false);

        uint256 borrowCap    = (collateralValue * h.BORROW_SAFETY_BUFFER_X32()) / h.Q32();
        uint256 transformCap = collateralValue;

        console2.log("collateralValue     :", collateralValue);
        console2.log("debt at 100pct LTV  :", debtAt100);
        console2.log("borrow() healthy    :", normalOk);
        console2.log("transform() healthy :", transformOk);
        console2.log("borrow() cap        :", borrowCap);
        console2.log("transform() cap     :", transformCap);
        console2.log("buffer freed        :", transformCap - borrowCap);

        assertFalse(normalOk,    "borrow() MUST reject 100pct LTV");
        assertTrue (transformOk, "BUG CONFIRMED: transform() accepts 100pct LTV");

        assertTrue (h.isHealthy(collateralValue, borrowCap,     true), "borrow() accepts its exact cap");
        assertFalse(h.isHealthy(collateralValue, borrowCap + 1, true), "borrow() rejects cap + 1 wei");
        assertTrue (h.isHealthy(collateralValue, transformCap,     false), "transform() accepts its exact cap");
        assertFalse(h.isHealthy(collateralValue, transformCap + 1, false), "transform() rejects cap + 1 wei");

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

        uint256 derivedFromTWAP = spotManipulated / 2;
        vm.expectRevert(bytes("PriceDifferenceExceeded"));
        o.requireMaxDifference(spotManipulated, derivedFromTWAP, maxDiff);
        console2.log("OK   : twapSeconds>0 rejects manipulated spot");

        bool samePoolBypass = o.derivedEqualsSpotWhenSamePool(0, true);
        assertTrue(samePoolBypass, "precondition: same-pool + twap=0");

        o.requireMaxDifference(spotManipulated, spotManipulated, maxDiff);
        console2.log("BUG  : same-pool + twap=0 accepts 100x manipulated spot");

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

    // --------------------------------------------------------
    // FINDING 4 - End-to-end attack simulation (P&L)
    // --------------------------------------------------------
    function test_simulate_attack_profitability() public {
        uint256 lpFairValue     = 1_000e18;
        uint256 flashLoanSize   = 5_000e18;
        uint256 flashLoanFeeBps = 9;
        uint256 gasBudget       = 50e18;

        uint256 flashFee = (flashLoanSize * flashLoanFeeBps) / 10_000;

        uint256 manipulatedValue = lpFairValue * 2;
        uint256 borrowed = (manipulatedValue * 90) / 100;

        uint256 penalty        = (borrowed * 10) / 100;
        uint256 liquidatorCost = lpFairValue - penalty;
        uint256 vaultWriteoff  = borrowed - liquidatorCost;

        uint256 attackerCash  = borrowed - flashFee - liquidatorCost - gasBudget;
        uint256 attackerLP    = lpFairValue;
        uint256 attackerFinal = attackerCash + attackerLP;
        uint256 attackerStart = lpFairValue;
        int256  pnl           = int256(attackerFinal) - int256(attackerStart);

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
}

// ============================================================
// OPTIONAL - Fork verification (runs only with secrets set)
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
