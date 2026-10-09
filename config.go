package main

import "github.com/ethereum/go-ethereum/common"

const MorphoGraphQLURL = "https://api.morpho.org/graphql"

// Filter thresholds. These are the only knobs that decide what
// survives from raw discovery to the scan surface.
const (
	// A market survives only if at least this many distinct
	// protocols are attached to it.
	MinProtocolsPerMarket = 2

	// A protocol survives only if its own TVL (or its allocation
	// to the market, whichever is available) exceeds this.
	MinProtocolTVLUSD = 50_000
)

// Protocol categories.
const (
	catLeveragedYieldFarm = "leveraged-yield-farm"
	catDeltaNeutralVault  = "delta-neutral-vault"
	catLPCollateral       = "lp-collateral-lender"
	catERC4626YieldVault  = "erc4626-yield-vault"
	catUnknown            = "unknown-protocol"
)

// Confirmation thresholds (pair-aware).
const (
	MinDeltaPctStableStable     = 0.3
	MinDeltaPctVolatileStable   = 1.0
	MinDeltaPctVolatileVolatile = 2.0
	MinDeltaPctFloor            = 0.1
)

// Selectors.
var (
	SelGetReserves     = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	SelSlot0           = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()
	SelLatestRound     = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
	SelObserve         = []byte{0x88, 0x3b, 0xdb, 0xfd} // observe()
	SelPrice           = []byte{0xa0, 0x35, 0xb1, 0xfe} // price()
	SelConvertToAssets = []byte{0x07, 0xa2, 0xd3, 0x24} // convertToAssets(uint256)
	SelTotalAssets     = []byte{0x01, 0xe1, 0xa0, 0x5f} // totalAssets()
	SelStable          = []byte{0x22, 0xbe, 0x12, 0xe4} // stable()
	SelFeeProtocol     = []byte{0x82, 0x06, 0xbc, 0x24} // feeProtocol()
)

// AMM storage slots.
const (
	SlotUniswapV2Reserves        = 8
	SlotUniswapV3Slot0           = 0
	SlotAerodromeV2Reserve0      = 12
	SlotAerodromeSlipstreamSlot0 = 0
)

// Reference addresses.
var (
	MorphoBlueAddress = common.HexToAddress("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb")
	USDCBase          = common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	DAIBase           = common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb")
	EURCBase          = common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42")
	USDTBase          = common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2")
)
