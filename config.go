package main

import "github.com/ethereum/go-ethereum/common"

// =============================================================
// Morpho Blue GraphQL API
// =============================================================

const MorphoGraphQLURL = "https://api.morpho.org/graphql"

// =============================================================
// Confirmation threshold
// =============================================================

// MinDeltaPct is the minimum |Δ oracle.price()| / baseline required
// to mark a market CONFIRMED, in percent (2.0 = 2%).
const MinDeltaPct = 2.0

// =============================================================
// Selectors
// =============================================================

var (
	// Spot AMM reads — flag oracles that use these.
	SelGetReserves = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	SelSlot0       = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()
	SelBalanceOf   = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	SelTotalSupply = []byte{0x18, 0x16, 0x0d, 0xdd} // totalSupply()

	// Robust feeds — whitelist oracles that use these.
	SelLatestRound = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
	SelObserve     = []byte{0x88, 0x3b, 0xdb, 0xfd} // observe()

	// Morpho IOracle interface.
	// Verify with: cast sig "price()"
	SelPrice = []byte{0xa0, 0x35, 0xb1, 0xfe} // price()

	// AMM kind detection (used by simulation.go).
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

// MorphoBlueAddress is used only for logging / context. Discovery is
// API-based; no on-chain enumeration.
var MorphoBlueAddress = common.HexToAddress(
	"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
)
