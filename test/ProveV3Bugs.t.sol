// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

interface IV3Vault {
    function BORROW_SAFETY_BUFFER_X32() external view returns (uint32);
    function asset() external view returns (address);
    function oracle() external view returns (address);
    function tokenConfigs(address) external view returns (
        uint32 collateralFactorX32,
        uint32 collateralValueLimitFactorX32,
        uint192 totalDebtShares
    );
}

interface IV3Oracle {
    function referenceToken() external view returns (address);
    function feedConfigs(address) external view returns (
        address feed,
        uint32 maxFeedAge,
        uint8 feedDecimals,
        uint8 tokenDecimals,
        uint32 twapSeconds,
        address pool,
        bool isToken0,
        uint8 mode,
        uint16 maxDifference
    );
}

interface IUniswapV3Pool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function fee() external view returns (uint24);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract ProveV3BugsFork is Test {
    address V3_VAULT;
    address USDC;
    address AAVE_POOL;
    address WETH_USDC_POOL;

    IV3Vault  vault;
    IV3Oracle oracle;

    // Parse lowercase hex string as address. No checksum validation, no unicode.
    function _addr(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        require(b.length >= 40, "too short");
        uint256 start = b.length - 40;
        uint160 result = 0;
        for (uint256 i = start; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            uint8 d;
            if (c >= 48 && c <= 57) d = c - 48;
            else if (c >= 97 && c <= 102) d = c - 87;
            else if (c >= 65 && c <= 70) d = c - 55;
            else revert("bad hex");
            result = (result << 4) | uint160(d);
        }
        return address(result);
    }

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));

        V3_VAULT       = _addr("0x36aeae0e411a1e28372e0d66f02e57744ebe7599");
        USDC           = _addr("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
        AAVE_POOL      = _addr("0xa238dd80c259a72e81d7e4664a9801593f98d1c5");
        WETH_USDC_POOL = _addr("0xd0b53d9277642d899df5c87a3966a349a798f224");

        vault  = IV3Vault(V3_VAULT);
        oracle = IV3Oracle(vault.oracle());
    }

    // ---------------------------------------------------------
    // F1 - buffer constant on-chain
    // ---------------------------------------------------------
    function test_F1_buffer_constant() public {
        uint32  buffer   = vault.BORROW_SAFETY_BUFFER_X32();
        uint32  expected = uint32((uint256(2 ** 32) * 95) / 100);
        address asset    = vault.asset();

        console2.log("=== F1: BUFFER CONSTANT ===");
        console2.log("BORROW_SAFETY_BUFFER_X32:", buffer);
        console2.log("expected 95pct of 2^32  :", expected);
        console2.log("vault asset             :", asset);

        assertEq(buffer, expected, "buffer matches source");
        assertEq(asset, USDC, "asset is USDC");
    }

    // ---------------------------------------------------------
    // F2 - scan every condition the same-pool bypass needs
    // ---------------------------------------------------------
    function test_F2_full_confirm() public {
        console2.log("=== F2: ORACLE SAME-POOL SCAN ===");
        console2.log("oracle:", address(oracle));

        address refToken = oracle.referenceToken();
        (uint32 refCF,,) = vault.tokenConfigs(refToken);
        bool refIsCollateral = refCF > 0;
        console2.log("referenceToken:", refToken);
        console2.log("referenceToken CF:", refCF);
        console2.log("referenceToken is collateral:", refIsCollateral);

        string[] memory tokenStrs = new string[](10);
        tokenStrs[0] = "0x4200000000000000000000000000000000000006"; // WETH
        tokenStrs[1] = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; // USDC
        tokenStrs[2] = "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"; // cbBTC
        tokenStrs[3] = "0x50c5725949a6f0c72e6c4a641f24049a917db0cb"; // DAI
        tokenStrs[4] = "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2"; // USDT
        tokenStrs[5] = "0xc1cba3fcea344f92d9239c08c0568f6f2f0ee452"; // wstETH
        tokenStrs[6] = "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22"; // cbETH
        tokenStrs[7] = "0x940181a94a35a4569e4529a3cdfb74e38fd98631"; // AERO
        tokenStrs[8] = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"; // EURC
        tokenStrs[9] = "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"; // USDbC

        uint256 collateralCount = 0;
        uint256 vulnCount = 0;

        for (uint256 i = 0; i < tokenStrs.length; i++) {
            address T = _addr(tokenStrs[i]);
            (uint32 cf,,) = vault.tokenConfigs(T);
            if (cf == 0) continue;
            collateralCount++;

            (
                ,, ,,
                uint32 twap,
                address pool,
                bool isToken0,
                uint8 mode,
                uint16 maxDiff
            ) = oracle.feedConfigs(T);

            console2.log("---");
            console2.log("token:", T);
            console2.log("  CF:", cf);
            console2.log("  twap:", twap);
            console2.log("  mode:", mode);
            console2.log("  pool:", pool);
            console2.log("  isToken0:", isToken0);
            console2.log("  maxDiff:", maxDiff);

            if (twap != 0 || mode != 4) {
                console2.log("  NOT VULNERABLE (twap/mode)");
                continue;
            }
            if (pool == address(0) || pool.code.length == 0) {
                console2.log("  NOT VULNERABLE (bad pool)");
                continue;
            }

            IUniswapV3Pool p = IUniswapV3Pool(pool);
            address p0 = p.token0();
            address p1 = p.token1();
            uint24 f = p.fee();
            console2.log("  pool.token0:", p0);
            console2.log("  pool.token1:", p1);
            console2.log("  pool.fee:", f);

            bool oriented = isToken0
                ? (p0 == T && p1 == refToken)
                : (p1 == T && p0 == refToken);

            if (!oriented) {
                console2.log("  NOT VULNERABLE (orientation)");
                continue;
            }
            if (!refIsCollateral) {
                console2.log("  NOT VULNERABLE (ref not collateral)");
                continue;
            }

            console2.log("  VULNERABLE: FINDING 2 CONFIRMED FOR THIS TOKEN");
            vulnCount++;
        }

        console2.log("=== F2 SUMMARY ===");
        console2.log("scanned:", tokenStrs.length);
        console2.log("collateral:", collateralCount);
        console2.log("vulnerable:", vulnCount);

        if (vulnCount > 0) {
            console2.log("FINDING 2 IS LIVE ON BASE MAINNET");
        } else {
            console2.log("Finding 2 NOT exploitable with current configuration");
        }
    }

    // ---------------------------------------------------------
    // F3 - economic preconditions
    // ---------------------------------------------------------
    function test_F3_economic_preconditions() public {
        console2.log("=== F3: ECONOMIC PRECONDITIONS ===");

        uint256 poolUsdc = IERC20(USDC).balanceOf(WETH_USDC_POOL);
        console2.log("WETH/USDC pool USDC balance:", poolUsdc);

        uint256 flashNeeded = poolUsdc * 2;
        console2.log("Flash needed for 2x swing:", flashNeeded);

        uint256 available = _aaveAvailableUSDC();
        console2.log("Aave V3 available USDC:", available);

        if (available >= flashNeeded) {
            console2.log("PRECONDITIONS MET: flash 2x pool depth via Aave");
        } else {
            console2.log("PRECONDITIONS NOT MET: Aave insufficient");
        }

        assertGt(poolUsdc, 100e6, "pool has meaningful USDC");
    }

    function _aaveAvailableUSDC() internal view returns (uint256) {
        // getReserveData(address) return layout:
        //   slot 9  = aTokenAddress         (offset 8*32  = 256)
        //   slot 11 = variableDebtTokenAddress (offset 10*32 = 320)
        (bool ok, bytes memory ret) = AAVE_POOL.staticcall(
            abi.encodeWithSignature("getReserveData(address)", USDC)
        );
        if (!ok || ret.length < 480) return 0;

        address aToken;
        address vDebt;
        assembly {
            aToken := and(mload(add(ret, 288)), 0xffffffffffffffffffffffffffffffffffffffff)
            vDebt  := and(mload(add(ret, 352)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
        if (aToken == address(0) || vDebt == address(0)) return 0;

        uint256 aT = IERC20(aToken).totalSupply();
        uint256 vD = IERC20(vDebt).totalSupply();
        return aT > vD ? aT - vD : 0;
    }
}
