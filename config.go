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
// reserve moves the reported LP price well under 1%. We gate on
// the *class* of the pair instead.
//
//   stable/stable     -> 0.3%   (a real oracle move is small but real)
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

// stableSymbols is the classifier for the pair-aware threshold.
// Upper-cased; matched against AssetInfo.Symbol.
var stableSymbols = map[string]bool{
	"USDC": true, "USDT": true, "DAI": true, "USDBC": true,
	"EURC": true, "CUSDO": true, "USDE": true, "SUSDE": true,
	"USDS": true, "SUSDS": true, "CRVUSD": true, "GHO": true,
	"USR": true, "RLUSD": true, "PYUSD": true, "FRAX": true,
}

// minDeltaForPair picks the confirmation threshold for a given pair.
func minDeltaForPair(loan, collateral AssetInfo) float64 {
	l := strings.ToUpper(loan.Symbol)
	c := strings.ToUpper(collateral.Symbol)
	ls := stableSymbols[l]
	cs := stableSymbols[c]
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

var MorphoBlueAddress = common.HexToAddress(
	"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
)
