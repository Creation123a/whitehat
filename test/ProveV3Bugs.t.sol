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
    struct FeedConfig {
        address feed;
        uint32  maxFeedAge;
        uint8   feedDecimals;
        uint8   tokenDecimals;
        uint32  twapSeconds;
        address pool;
        bool    isToken0;
        uint8   mode;
        uint16  maxDifference;
    }
    function referenceToken() external view returns (address);
    function feedConfigs(address) external view returns (FeedConfig memory);
}

interface IUniswapV3Pool {
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract ProveV3BugsFork is Test {
    IV3Vault  vault;
    IV3Oracle oracle;
    address   usdc;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
        vault  = IV3Vault(vm.parseAddress("0x36aeae0e411a1e28372e0d66f02e57744ebe7599"));
        oracle = IV3Oracle(vault.oracle());
        usdc   = vm.parseAddress("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
    }

    // ---------------------------------------------------------
    // F1 - buffer constant on-chain
    // ---------------------------------------------------------
    function test_F1_buffer_constant() public {
        uint32 buffer   = vault.BORROW_SAFETY_BUFFER_X32();
        uint32 expected = uint32((uint256(2 ** 32) * 95) / 100);
        address asset   = vault.asset();

        console2.log("F1 buffer  :", buffer);
        console2.log("F1 expected:", expected);
        console2.log("F1 asset   :", asset);

        assertEq(buffer, expected, "buffer mismatch");
        assertEq(asset, usdc, "asset not USDC");
    }

    // ---------------------------------------------------------
    // F2 - discover every configured token via logs, scan each
    // ---------------------------------------------------------
    function test_F2_same_pool_scan() public {
        address ref = oracle.referenceToken();
        (uint32 refCF, , ) = vault.tokenConfigs(ref);
        bool refIsCollateral = refCF > 0;

        console2.log("F2 oracle    :", address(oracle));
        console2.log("F2 refToken  :", ref);
        console2.log("F2 refCollat :", refIsCollateral);

        uint256 vuln = _scanConfigured(ref, refIsCollateral);

        console2.log("F2 vulnerable:", vuln);
        if (vuln > 0) {
            console2.log("FINDING 2 CONFIRMED ON BASE MAINNET");
        } else {
            console2.log("Finding 2 not exploitable with current config");
        }
    }

    function _scanConfigured(address ref, bool refIsCollateral)
        internal
        returns (uint256 vulnCount)
    {
        bytes memory raw = vm.rpc(
            "eth_getLogs",
            string.concat(
                '{"address":"', vm.toString(address(vault)),
                '","fromBlock":"0x0","toBlock":"latest","topics":["',
                vm.toString(keccak256("SetTokenConfig(address,uint32,uint32)")),
                '"]}'
            )
        );

        string memory rawStr = string(raw);
        string[] memory dataList = vm.parseJsonStringArray(rawStr, ".result[*].data");
        console2.log("F2 logs fetched:", dataList.length);

        address[] memory seen = new address[](dataList.length);
        uint256 seenCount = 0;

        for (uint256 i = 0; i < dataList.length; i++) {
            address token = _decodeTokenFromData(dataList[i]);
            if (token == address(0)) continue;
            if (_contains(seen, seenCount, token)) continue;

            seen[seenCount] = token;
            seenCount++;

            (uint32 cf, , ) = vault.tokenConfigs(token);
            if (cf == 0) continue;

            if (_isVulnerable(token, ref, refIsCollateral)) {
                console2.log("VULNERABLE:", token);
                vulnCount++;
            }
        }
    }

    // SetTokenConfig(address,uint32,uint32) - token is NOT indexed,
    // so it sits as the first 20 bytes of data.
    function _decodeTokenFromData(string memory data)
        internal
        pure
        returns (address)
    {
        bytes memory b = bytes(data);
        if (b.length < 66) return address(0);

        uint160 v = 0;
        for (uint256 i = 2; i < 42; i++) {
            v = (v << 4) | uint160(_hexVal(uint8(b[i])));
        }
        return address(v);
    }

    function _hexVal(uint8 c) internal pure returns (uint8) {
        if (c >= 48 && c <= 57) return c - 48;
        if (c >= 97 && c <= 102) return c - 87;
        if (c >= 65 && c <= 70) return c - 55;
        revert("bad hex");
    }

    function _contains(address[] memory arr, uint256 n, address x)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < n; i++) {
            if (arr[i] == x) return true;
        }
        return false;
    }

    function _isVulnerable(address T, address ref, bool refIsCollateral)
        internal
        view
        returns (bool)
    {
        (uint32 cf, , ) = vault.tokenConfigs(T);
        if (cf == 0) return false;

        IV3Oracle.FeedConfig memory cfg = oracle.feedConfigs(T);
        if (cfg.twapSeconds != 0) return false;
        if (cfg.mode != 4) return false;

        if (cfg.pool == address(0)) return false;
        if (cfg.pool.code.length == 0) return false;

        IUniswapV3Pool p = IUniswapV3Pool(cfg.pool);
        address p0 = p.token0();
        address p1 = p.token1();

        bool oriented = cfg.isToken0
            ? (p0 == T && p1 == ref)
            : (p1 == T && p0 == ref);
        if (!oriented) return false;

        if (!refIsCollateral) return false;

        return true;
    }

    // ---------------------------------------------------------
    // F3 - economic preconditions
    // ---------------------------------------------------------
    function test_F3_economics() public {
        address poolAddr     = vm.parseAddress("0xd0b53d9277642d899df5c87a3966a349a798f224");
        address aavePoolAddr = vm.parseAddress("0xa238dd80c259a72e81d7e4664a9801593f98d1c5");

        uint256 poolUsdc = IERC20(usdc).balanceOf(poolAddr);
        uint256 flash2x  = poolUsdc * 2;
        uint256 avail    = _aaveAvail(aavePoolAddr);

        console2.log("F3 pool USDC  :", poolUsdc);
        console2.log("F3 flash 2x   :", flash2x);
        console2.log("F3 aave avail :", avail);

        if (avail >= flash2x) {
            console2.log("PRECONDITIONS MET");
        } else {
            console2.log("PRECONDITIONS NOT MET");
        }

        assertGt(poolUsdc, 100e6, "pool too shallow");
    }

    function _aaveAvail(address aavePool) internal view returns (uint256) {
        (bool ok, bytes memory ret) = aavePool.staticcall(
            abi.encodeWithSignature("getReserveData(address)", usdc)
        );
        if (!ok || ret.length < 480) return 0;

        address aT;
        address vD;
        assembly {
            aT := and(mload(add(ret, 288)), 0xffffffffffffffffffffffffffffffffffffffff)
            vD := and(mload(add(ret, 352)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
        if (aT == address(0) || vD == address(0)) return 0;

        uint256 aBal = IERC20(aT).totalSupply();
        uint256 vBal = IERC20(vD).totalSupply();
        return aBal > vBal ? aBal - vBal : 0;
    }
}
