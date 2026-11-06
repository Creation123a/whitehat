// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

contract StakeDAODiagnostic is Test {
    address constant ROUTER = 0x0f542fA75c871EB1b93Ef881b73e46acF733392f;
    address constant ALLMIGHT = 0xDBd24b092f686b12650EC1450e3A7138F714506c;
    
    address[3] VAULTS = [
        0x8EDCC305E633d29BFB383872e79401c506cE9E6f, // V2
        0x4b7D98a652C4ca87B3EAE4A64F7FF852de2Ef9B7, // CORE
        0x13AA4f80AD5F06cE4f1A3a3cA58C37059F0EE4c5  // V1 Legacy
    ];

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testFindFundedVault() public {
        for (uint i = 0; i < VAULTS.length; i++) {
            address vault = VAULTS[i];
            console.log("--- Vault:", vault, "---");

            // Check Balance
            (bool success, bytes memory data) = vault.staticcall(
                abi.encodeWithSignature("balanceOf(address)", ALLMIGHT)
            );
            if (success) {
                console.log("  ALLMIGHT Shares:", abi.decode(data, (uint256)));
            } else {
                console.log("  Balance call failed.");
            }

            // Check Allowance
            (success, data) = vault.staticcall(
                abi.encodeWithSignature("allowance(address,address)", ALLMIGHT, ROUTER)
            );
            if (success) {
                console.log("  Router Allowance:", abi.decode(data, (uint256)));
            } else {
                console.log("  Allowance call failed.");
            }
        }
    }
}
