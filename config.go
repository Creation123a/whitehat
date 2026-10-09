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
// Confirmation thresholds (pair-aware)
// =============================================================
//
// A single global 2.0% gate misses real LP-oracle manipulations:
// for a stable/stable pool like cUSDO/USDC a +10% shift on one
// reserve moves the reported LP price well under 1%.
//
//   stable/stable     -> 0.3%
//   volatile/stable   -> 1.0%
//   volatile/volatile -> 2.0%
//
const (
	MinDeltaPctStableStable     = 0.3
	MinDeltaPctVolatileStable   = 1.0
	MinDeltaPctVolatileVolatile = 2.0
)

// MinDeltaPct is retained only as documentation / fallback. New
// code should call minDeltaForPair.
const MinDeltaPct = MinDeltaPctStableStable

// =============================================================
// Stablecoin classification (Issue C)
// =============================================================
//
// Address-first, symbol-second. Symbols drift: bridged USDC
// becomes "USDC.e", rebasing stables append ".b" or "+", and
// wrapped variants invent new tickers. Address is authoritative;
// the symbol path is a fallback for tokens we haven't enumerated.

var stableAddresses = map[common.Address]bool{
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): true, // USDC
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): true, // USDbC
	common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"): true, // DAI
	common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"): true, // EURC
	common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"): true, // USDT (Base)
	common.HexToAddress("0x417Ac0e078398C154EdFadD9Ef675d30Be60Af93"): true, // crvUSD (Base)
	common.HexToAddress("0x6Bb7a212910682DCFdbd5BCBb3e28FB4E8da10Ee"): true, // GHO (Base)
	common.HexToAddress("0x85483696Cc9970Ad9EdD786b2C5ef735F38D156f"): true, // axlUSDC
	common.HexToAddress("0xEB466342C4d449BC9f53A865D5Cb90586f405215"): true, // axlUSDC (alt)
	common.HexToAddress("0xb755B949C126C04e0348dD29Ccf5069FAb3ce70E"): true, // axlUSDT
	common.HexToAddress("0x4A3A6Dd60A34bB2Aba60D73B4C88315E9CeB6A3D"): true, // USD+
}

// stableSymbols is the symbol fallback. Values are normalized
// (uppercase, no .e/.b/+/ - suffix).
var stableSymbols = map[string]bool{
	"USDC": true, "USDT": true, "DAI": true, "USDBC": true,
	"EURC": true, "CUSDO": true, "USDE": true, "SUSDE": true,
	"USDS": true, "SUSDS": true, "CRVUSD": true, "GHO": true,
	"USR": true, "RLUSD": true, "PYUSD": true, "FRAX": true,
	"AXLUSDC": true, "AXLUSDT": true, "USD": true,
}

// isStableAsset classifies an asset as stable. Address wins over
// symbol because it is immune to symbol drift and rebasing wrappers.
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

// minDeltaForPair picks the confirmation threshold for a given pair.
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
// Selectors
// =============================================================

var (
	// Spot AMM reads — flag oracles that use these.
	SelGetReserves = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	SelSlot0       = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()
	SelBalanceOf   = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	SelTotalSupply = []byte{0x18, 0x16, 0x0d, 0xdd} // totalSupply()

	// Robust feeds.
	SelLatestRound = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
	SelObserve     = []byte{0x88, 0x3b, 0xdb, 0xfd} // observe()

	// Morpho IOracle interface.
	SelPrice = []byte{0xa0, 0x35, 0xb1, 0xfe} // price()

	// AMM kind detection.
	SelStable      = []byte{0x22, 0xbe, 0x12, 0xe4} // stable()
	SelFeeProtocol = []byte{0x82, 0x06, 0xbc, 0x24} // feeProtocol()
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
// Morpho Blue (reference)
// =============================================================
//
// Also used as the msg.sender for debug_traceCall so oracles that
// gate on the caller trace correctly (see tracePriceCall).

var MorphoBlueAddress = common.HexToAddress(
	"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
)
