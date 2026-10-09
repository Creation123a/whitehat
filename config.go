package main

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// Morpho Blue GraphQL API
// =============================================================

const MorphoGraphQLURL = "https://api.morpho.org/graphql"

// =============================================================
// DefiLlama API (protocol universe discovery)
// =============================================================

// DefiLlamaProtocolsURL returns every protocol the aggregator tracks,
// across all chains. Free, keyless, always USD-denominated TVL.
const DefiLlamaProtocolsURL = "https://api.llama.fi/protocols"

// DefiLlamaBaseChain is the chain name DefiLlama uses for Base.
const DefiLlamaBaseChain = "Base"

// TargetDefiLlamaCategories are the categories the scanner cares
// about. Filtering by these gives leveraged yield farms,
// delta-neutral vaults, LP-collateral lenders, and independent
// lending protocols on Base.
var TargetDefiLlamaCategories = map[string]bool{
	"Leveraged Farming": true,
	"Delta Neutral":     true,
	"LP Collateral":     true,
	"Lending":           true,
	"Yield":             true,
	"Yield Aggregator":  true,
}

// =============================================================
// SQD Portal (name -> address resolution)
// =============================================================

// SQDPortalURL is the public, permissionless SQD Portal endpoint.
// No API key required; rate-limited but sufficient for a scan run.
const SQDPortalURL = "https://portal.sqd.dev"

// =============================================================
// Pipeline filter thresholds
// =============================================================

const (
	// MinProtocolsPerMarket is kept for backward compat; the v6.0
	// pipeline no longer applies it by default.
	MinProtocolsPerMarket = 2

	// MinProtocolTVLUSD is the default dust threshold for both
	// DefiLlama protocol TVL and per-market allocation.
	MinProtocolTVLUSD = 50_000
)

// =============================================================
// Protocol categories
// =============================================================

const (
	catLeveragedYieldFarm = "leveraged-yield-farm"
	catDeltaNeutralVault  = "delta-neutral-vault"
	catLPCollateral       = "lp-collateral-lender"
	catERC4626YieldVault  = "erc4626-yield-vault"
	catUnknown            = "unknown-protocol"
)

// =============================================================
// Confirmation thresholds (pair-aware)
// =============================================================

const (
	MinDeltaPctStableStable     = 0.3
	MinDeltaPctVolatileStable   = 1.0
	MinDeltaPctVolatileVolatile = 2.0
	MinDeltaPctFloor            = 0.1
)

// =============================================================
// Selectors
// =============================================================

var (
	// Spot AMM reads — any of these anywhere in a traced pricing
	// path means the protocol has a manipulable leg.
	SelGetReserves = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	SelSlot0       = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()

	// Expanded spot-AMM selector set (v6.0).
	SelGetVirtualPrice = []byte{0xbb, 0x7b, 0x8b, 0x80} // get_virtual_price()
	SelGetPoolTokens   = []byte{0xf9, 0x4d, 0x46, 0x68} // getPoolTokens(bytes32)
	SelConsult         = []byte{0x0f, 0xdb, 0x11, 0xcf} // consult(address,uint256)
	SelGetPriceCumul   = []byte{0x25, 0x2c, 0x8c, 0xb6} // getPriceCumulative()

	// Robust feeds. Presence does NOT whitelist; it marks mixed-source.
	SelLatestRound = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
	SelObserve     = []byte{0x88, 0x3b, 0xdb, 0xfd} // observe(uint32[])
	SelLatestAns   = []byte{0x50, 0xd2, 0x5b, 0xcd} // latestAnswer()

	// Morpho IOracle interface.
	SelPrice = []byte{0xa0, 0x35, 0xb1, 0xfe} // price()

	// ERC-4626.
	SelConvertToAssets = []byte{0x07, 0xa2, 0xd3, 0x24}
	SelTotalAssets     = []byte{0x01, 0xe1, 0xa0, 0x5f}

	// AMM kind detection.
	SelStable      = []byte{0x22, 0xbe, 0x12, 0xe4} // stable()
	SelFeeProtocol = []byte{0x82, 0x06, 0xbc, 0x24} // feeProtocol()

	// Common strategy entry points (probed by future v6.0 probe.go).
	SelDepositUint      = []byte{0xb6, 0xb5, 0x5f, 0x25} // deposit(uint256)
	SelWithdrawUint     = []byte{0x2e, 0x1a, 0x7d, 0x4d} // withdraw(uint256)
	SelDepositPayable   = []byte{0xd0, 0xe3, 0x0d, 0xb0} // deposit()
	SelWithdrawPayable  = []byte{0x3c, 0xcf, 0xd6, 0x0b} // withdraw()
	SelHarvest          = []byte{0x46, 0x41, 0x25, 0x7d} // harvest()
	SelRebalance        = []byte{0xc8, 0xa2, 0x5d, 0x3d} // rebalance()
)

// =============================================================
// AMM storage slots
// =============================================================

const (
	SlotUniswapV2Reserves        = 8
	SlotUniswapV3Slot0           = 0
	SlotAerodromeV2Reserve0      = 12
	SlotAerodromeV2Reserve1      = 13
	SlotAerodromeSlipstreamSlot0 = 0
)

// =============================================================
// Stablecoin classification (address-first, symbol-second)
// =============================================================

var stableAddresses = map[common.Address]bool{
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): true, // USDC
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): true, // USDbC
	common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"): true, // DAI
	common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"): true, // EURC
	common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"): true, // USDT
	common.HexToAddress("0x417Ac0e078398C154EdFadD9Ef675d30Be60Af93"): true, // crvUSD
	common.HexToAddress("0x6Bb7a212910682DCFdbd5BCBb3e28FB4E8da10Ee"): true, // GHO
	common.HexToAddress("0x85483696Cc9970Ad9EdD786b2C5ef735F38D156f"): true, // axlUSDC
	common.HexToAddress("0xEB466342C4d449BC9f53A865D5Cb90586f405215"): true, // axlUSDC alt
	common.HexToAddress("0xb755B949C126C04e0348dD29Ccf5069FAb3ce70E"): true, // axlUSDT
	common.HexToAddress("0x4A3A6Dd60A34bB2Aba60D73B4C88315E9CeB6A3D"): true, // USD+
}

var stableSymbols = map[string]bool{
	"USDC": true, "USDT": true, "DAI": true, "USDBC": true,
	"EURC": true, "CUSDO": true, "USDE": true, "SUSDE": true,
	"USDS": true, "SUSDS": true, "CRVUSD": true, "GHO": true,
	"USR": true, "RLUSD": true, "PYUSD": true, "FRAX": true,
	"AXLUSDC": true, "AXLUSDT": true, "USD": true,
}

func isStableAsset(a AssetInfo) bool {
	if a.Address != (common.Address{}) && stableAddresses[a.Address] {
		return true
	}
	return stableSymbols[normalizeStableSymbol(a.Symbol)]
}

func normalizeStableSymbol(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	for _, suffix := range []string{".E", ".B", "+", "-"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

func minDeltaForPair(loan, collateral AssetInfo) float64 {
	ls := isStableAsset(loan)
	cs := isStableAsset(collateral)
	switch {
	case ls && cs:
		return MinDeltaPctStableStable
	case ls || cs:
		return MinDeltaPctVolatileStable
	default:
		return MinDeltaPctVolatileVolatile
	}
}

// =============================================================
// Reference addresses
// =============================================================

var (
	MorphoBlueAddress = common.HexToAddress(
		"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb")

	WETHBase = common.HexToAddress("0x4200000000000000000000000000000000000006")
	USDCBase = common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	DAIBase  = common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb")
	EURCBase = common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42")
	USDTBase = common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2")
)
