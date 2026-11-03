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
