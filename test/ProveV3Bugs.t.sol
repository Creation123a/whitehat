// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

interface IV3Vault {
    function BORROW_SAFETY_BUFFER_X32() external view returns (uint32);
    function asset() external view returns (address);
}

interface IV3Oracle {
    function feedConfigs(address) external view returns (
        address feed, uint32 maxFeedAge, uint8 feedDecimals, uint8 tokenDecimals,
        uint32 twapSeconds, address pool, bool isToken0, uint8 mode, uint16 maxDifference
    );
    function maxPoolPriceDifference() external view returns (uint16);
}

interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint8 feeProtocol, bool unlocked
    );
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract ProveV3BugsFork is Test {

    address constant V3_VAULT       = 0x36AEAe0E411a1E28372e0d66f02E57744EbE7599;
    address constant V3_ORACLE      = 0x6243d2F41b4ec944F731f647589E28d9745a2674;
    address constant USDC           = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant WETH           = 0x4200000000000000000000000000000000000006;
    address constant CBBTC          = 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf;
    address constant AAVE_V3_POOL   = 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5;
    address constant WETH_USDC_POOL = 0xd0b53D9277642d899DF5C87A3966A349A798F224;

    IV3Vault  vault;
    IV3Oracle oracle;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
        vault  = IV3Vault(V3_VAULT);
        oracle = IV3Oracle(V3_ORACLE);
    }

    function test_fork_F1_constants() public {
        uint32  buffer   = vault.BORROW_SAFETY_BUFFER_X32();
        address asset    = vault.asset();
        uint32  expected = uint32((uint256(2 ** 32) * 95) / 100);

        console2.log("BORROW_SAFETY_BUFFER_X32 on-chain:", buffer);
        console2.log("expected (95pct of 2^32)         :", expected);
        console2.log("vault asset                      :", asset);

        assertEq(buffer, expected, "buffer matches source");
        assertEq(asset, USDC, "vault asset is USDC");
    }

    function test_fork_F2_twap_scan() public {
        address[3] memory tokens = [WETH, USDC, CBBTC];

        for (uint256 i = 0; i < 3; i++) {
            (
                ,, ,,
                uint32 twapSeconds,
                address pool,
                bool isToken0,
                uint8 mode,
                uint16 maxDiff
            ) = oracle.feedConfigs(tokens[i]);

            console2.log("token        :", tokens[i]);
            console2.log("  twapSeconds:", twapSeconds);
            console2.log("  pool       :", pool);
            console2.log("  isToken0   :", isToken0);
            console2.log("  mode       :", mode);
            console2.log("  maxDiff    :", maxDiff);

            if (twapSeconds == 0 && mode == 4) {
                console2.log("  VULNERABLE CONFIG DETECTED");
            }
        }

        console2.log("global maxPoolPriceDifference:", oracle.maxPoolPriceDifference());
    }

    function test_fork_F3_economic_preconditions() public {
        uint256 aaveUsdc = IERC20(USDC).balanceOf(AAVE_V3_POOL);
        uint256 poolUsdc = IERC20(USDC).balanceOf(WETH_USDC_POOL);

        IUniswapV3Pool pool = IUniswapV3Pool(WETH_USDC_POOL);
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        uint256 priceX96 = (uint256(sqrtPriceX96) * uint256(sqrtPriceX96)) >> 96;

        uint256 flashSize = poolUsdc * 2;
        uint256 flashFee  = (flashSize * 5) / 10_000;

        console2.log("Aave USDC liquidity :", aaveUsdc);
        console2.log("Pool USDC balance   :", poolUsdc);
        console2.log("Flash size needed   :", flashSize);
        console2.log("Flash fee (0.05pct) :", flashFee);
        console2.log("WETH/USDC priceX96  :", priceX96);

        assertGt(aaveUsdc, 0, "Aave has USDC");
        assertGt(poolUsdc, 0, "pool has USDC");
    }
}
