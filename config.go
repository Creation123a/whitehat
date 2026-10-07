package main

import (
	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// Protocol addresses (Base mainnet)
// =============================================================

// Morpho Blue on Base.
// Source: morpho-org/blue-points-subgraph deploy commit, Base startBlock 13977148.
var MorphoBlueAddress = common.HexToAddress(
	"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
)

// Aave V3 Pool proxy on Base.
// Source: Aave V3 deployments; L2Pool at this address.
var AaveV3PoolAddress = common.HexToAddress(
	"0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
)

// =============================================================
// Discovery window
// =============================================================
// LogChunkSize is the maximum block range per eth_getLogs call.
// Alchemy free tier caps this at 10. PAYG and most other providers
// allow much larger ranges (1_000–10_000). Set to 0 to disable chunking.
var LogChunkSize = uint64(10)
// BlockWindowSize bounds the Transfer-log scan in discovery.go.
// 50,000 blocks ≈ 27.7 hours on Base (2 s blocks).
var BlockWindowSize = uint64(500)

// MorphoDeployBlock is the block Morpho Blue was deployed on Base.
// Used as the lower bound for CreateMarket replay when non-zero.
// Set to 13977148 to scan full market history (slower).
var MorphoDeployBlock = uint64(0) // 0 = use BlockWindowSize

// =============================================================
// Token registry
// =============================================================

// TokenInfo describes one ERC-20 for TVL pricing.
type TokenInfo struct {
	Symbol        string
	Decimals      uint8
	ChainlinkFeed common.Address
}

// TokenRegistry maps underlying token address -> metadata.
//
// All Chainlink feed addresses verified against Chainlink docs,
// Exactly Protocol docs, and Zerolend docs for Base mainnet.
var TokenRegistry = map[common.Address]TokenInfo{
	// WETH
	common.HexToAddress("0x4200000000000000000000000000000000000006"): {
		Symbol:        "WETH",
		Decimals:      18,
		ChainlinkFeed: common.HexToAddress("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"),
	},
	// USDC (native)
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): {
		Symbol:        "USDC",
		Decimals:      6,
		ChainlinkFeed: common.HexToAddress("0x7e860098F58bBFC8648a4311b374B1D669a2bc6B"),
	},
	// USDbC (bridged USDC)
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): {
		Symbol:        "USDbC",
		Decimals:      6,
		ChainlinkFeed: common.HexToAddress("0x7e860098F58bBFC8648a4311b374B1D669a2bc6B"),
	},
	// cbETH
	common.HexToAddress("0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22"): {
		Symbol:        "cbETH",
		Decimals:      18,
		ChainlinkFeed: common.HexToAddress("0xd7818272B9e248357d13057AAb0B417aF31E817d"),
	},
	// wstETH — uses ETH/USD as a USD approximation.
	// A full implementation composes wstETH/ETH × ETH/USD.
	common.HexToAddress("0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452"): {
		Symbol:        "wstETH",
		Decimals:      18,
		ChainlinkFeed: common.HexToAddress("0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"),
	},
}

// =============================================================
// Aerodrome addresses (blocklist)
// =============================================================

var (
	// Aerodrome PoolFactory — creates V2-style pools.
	AerodromePoolFactory = common.HexToAddress(
		"0x420DD381b31aEf6683db6B902084cB0FFECe40Da",
	)

	// Aerodrome Router — swaps, liquidity management.
	AerodromeRouter = common.HexToAddress(
		"0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43",
	)

	// Aerodrome Slipstream Factory — concentrated liquidity pools.
	AerodromeSlipstreamFactory = common.HexToAddress(
		"0x5e7BB104d84c7CB9B682AaC2F3d509f5F406809A",
	)
)

// =============================================================
// AMM storage slots (simulation.go)
// =============================================================

const (
	// Uniswap V2 Pair — reserves packed at slot 8.
	SlotUniswapV2Reserves = 8

	// Uniswap V3 Pool — slot0 at slot 0.
	SlotUniswapV3Slot0 = 0

	// Aerodrome Pool.sol — reserve0 at slot 12.
	// TODO: verify via `cast storage <pool> 12` before first run.
	SlotAerodromeV2Reserve0 = 12

	// Aerodrome Pool.sol — reserve1 at slot 13.
	// TODO: verify via `cast storage <pool> 13` before first run.
	SlotAerodromeV2Reserve1 = 13

	// Aerodrome Slipstream CLPool — slot0 at slot 0.
	SlotAerodromeSlipstreamSlot0 = 0
)

// =============================================================
// Detection selector table (reference)
// =============================================================

var DetectionSelectors = map[string]string{
	"0x0902f1ac": "getReserves()",     // Uniswap V2 / Aerodrome V2 — spot
	"0x3850c7bd": "slot0()",           // Uniswap V3 / Slipstream — spot
	"0xfeaf968c": "latestRoundData()", // Chainlink — resistant
	"0x883bdbfd": "observe()",         // Uniswap V3 TWAP — resistant
}

// =============================================================
// Event topics (reference)
// =============================================================

var (
	TransferTopicRef = common.HexToHash(
		"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
	)

	// keccak256("CreateMarket(bytes32,(address,address,address,address,uint256))")
	MorphoCreateMarketTopicRef = common.HexToHash(
		"0xac4b2400f169220b0c0afdde7a0b32e775ba727ea1cb30b35f935cdaab8683ac",
	)
)
