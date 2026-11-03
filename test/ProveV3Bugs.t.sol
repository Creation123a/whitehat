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
    // Same struct shape as V3Oracle.TokenConfig. ABI matches the
    // auto-generated mapping getter, so returns decode as-is.
    struct FeedConfig {
        address feed;
        uint32 maxFeedAge;
        uint8 feedDecimals;
        uint8 tokenDecimals;
        uint32 twapSeconds;
        address pool;
        bool isToken0;
        uint8 mode;
        uint16 maxDifference;
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
    // F2 - full same-pool bypass scan
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
        // Fetch logs. vm.rpc returns the raw JSON as bytes.
        bytes memory raw = vm.rpc(
            "eth_getLogs",
            string.concat(
                '{"address":"', vm.toString(address(vault)),
                '","fromBlock":"0x0","toBlock":"latest","topics":["',
                vm.toString(keccak256("SetTokenConfig(address,uint32,uint32)")),
                '"]}'
            )
        );

        // Parse the JSON response to a string array of data fields.
        // path ".result[*].data" works with vm.parseJsonStringArray.
        string[] memory dataList = vm.parseJsonStringArray(raw, ".result[*].data");
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

    // data = 0x + 32-byte token + 32-byte cf + 32-byte limit.
    // token is the first 20 bytes of the first word.
    function _decodeTokenFromData(string memory data)
        internal
        pure
        returns (address)
    {
        bytes memory b = bytes(data);
        if (b.length < 66) return address(0); // "0x" + 64 hex

        uint160 v = 0;
        // token occupies chars [2..41] (40 hex chars = 20 bytes)
        for (uint256 i = 2; i < 42; i++) {
            v = (v << 4) | uint160(_hexVal(uint8(b[i])));
        }
        return address(v);
    }

    function _hexVal(uint8 c) internal pure returns (uint8) {
        if (c >= 48 && c <= 57) return c - 48;      // 0-9
        if (c >= 97 && c <= 102) return c - 87;     // a-f
        if (c >= 65 && c <= 70) return c - 55;      // A-F
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

    // ---------------------------------------------------------
    // F3 - economic preconditions (flash feasibility)
    // ---------------------------------------------------------
    function test_F3_economics() public {
        address poolAddr     = vm.parseAddress("0xd0b53d9277642d899df5c87a3966a349a798f224");
        address aavePoolAddr = vm.parseAddress("0xa238dd80c259a72e81d7e4664a9801593f98d1c5");

        uint256 poolUsdc = IERC20(usdc).balanceOf(poolAddr);
        uint256 flash2x  = poolUsdc * 2;
        uint256 avail    = _aaveAvail(aavePoolAddr);

        console2.log("F3 pool USDC   :", poolUsdc);
        console2.log("F3 flash 2x    :", flash2x);
        console2.log("F3 aave avail  :", avail);

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
        // getReserveData ABI layout, slot 8 = aToken, slot 10 = variableDebt
        // offset = ret + 32 + 32*slot
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
