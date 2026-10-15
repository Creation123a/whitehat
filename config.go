package main

import (
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// External APIs
// =============================================================

const (
	DefiLlamaProtocolsURL = "https://api.llama.fi/protocols"
	DefiLlamaBaseChain    = "Base"

	EtherscanBaseURL = "https://api.etherscan.io/v2/api"
	EtherscanChainID = 8453

	OpenRouterURL = "https://openrouter.ai/api/v1/chat/completions"
	// SQD Portal MCP endpoint. The scanner talks to the portal
	// over the stateless MCP 2026-07-28 protocol via the official
	// Go MCP SDK.
	SQDPortalMCPURL   = "https://portal.sqd.dev/mcp"
	SQDBaseNetwork    = "base-mainnet"
)

// =============================================================
// API Keys (injected via env or defaults)
// =============================================================

var (
	EtherscanAPIKey  = "ETN9EBPSA2P7QMWF1GM9MEITN14HVXIYUE"
	OpenRouterAPIKey = "" // set via OPENROUTER_API_KEY env
)

// =============================================================
// Phase 1: DefiLlama category filter
// =============================================================

// TargetCategories are the ONLY DefiLlama categories the scanner
// accepts per run. The workflow passes one keyword; the scanner
// matches DefiLlama's `category` field against it exactly.
var TargetCategories = map[string]bool{
	"Lending":            true,
	"Isolated Lending":   true,
	"Yield":              true,
	"Yield Aggregator":   true,
	"CDP":                true,
	"Leveraged Farming":  true,
}

// TVL bounds (USD), enforced from DefiLlama chainTvls["Base"].
const (
	MinTVLUSD = 50_000
	MaxTVLUSD = 10_000_000
)

// =============================================================
// Phase 2: SQD + Anvil fork
// =============================================================

const (
	requiredChainID = 31337
	anvilReadyMax   = 60 * time.Second
	anvilPollEvery  = 250 * time.Millisecond
)

// =============================================================
// Phase 3: Regex selectors (pricing bytecode scan)
// =============================================================

var (
	// Pricing selectors that mark a contract as a pricing engine.
	SelGetAssetPrice      = []byte{0xb3, 0x59, 0x6f, 0x07} // getAssetPrice(address)
	SelGetUnderlyingPrice = []byte{0xfc, 0x57, 0xd4, 0xdf} // getUnderlyingPrice(address)
	SelGetReserves        = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	SelSlot0              = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()
	SelGetVirtualPrice    = []byte{0xbb, 0x7b, 0x8b, 0x80} // get_virtual_price()
	SelLatestRound        = []byte{0xfe, 0xaf, 0x96, 0x8c} // latestRoundData()
	SelLatestAnswer       = []byte{0x50, 0xd2, 0x5b, 0xcd} // latestAnswer()
	SelObserve            = []byte{0x88, 0x3b, 0xdb, 0xfd} // observe(uint32[])
)

// =============================================================
// Phase 4: OpenRouter models (fallback chain)
// =============================================================

var LLMModels = []string{
	"poolside/laguna-s-2.1:free",
	"nvidia/nemotron-3.5-lightning:free",
}

// =============================================================
// Output
// =============================================================

const (
	catLeveragedYieldFarm = "leveraged-yield-farm"
	catDeltaNeutralVault  = "delta-neutral-vault"
	catLPCollateral       = "lp-collateral-lender"
	catERC4626YieldVault  = "erc4626-yield-vault"
	catUnknown            = "unknown-protocol"
)

// =============================================================
// Helpers
// =============================================================

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

var stableAddresses = map[common.Address]bool{
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): true, // USDC
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): true, // USDbC
	common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"): true, // DAI
	common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"): true, // EURC
	common.HexToAddress("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"): true, // USDT
	common.HexToAddress("0x417Ac0e078398C154EdFadD9Ef675d30Be60Af93"): true, // crvUSD
	common.HexToAddress("0x6Bb7a212910682DCFdbd5BCBb3e28FB4E8da10Ee"): true, // GHO
}

var stableSymbols = map[string]bool{
	"USDC": true, "USDT": true, "DAI": true, "USDBC": true,
	"EURC": true, "CUSDO": true, "USDE": true, "SUSDE": true,
	"USDS": true, "SUSDS": true, "CRVUSD": true, "GHO": true,
}
