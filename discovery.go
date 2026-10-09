package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// Core domain types
// =============================================================

type AssetInfo struct {
	Address  common.Address
	Symbol   string
	Name     string
	Decimals uint8
}

type MorphoMarket struct {
	MarketID        string
	Oracle          common.Address
	OracleType      string
	Warnings        []string
	Listed          bool
	LoanAsset       AssetInfo
	CollateralAsset AssetInfo
	LLTV            string
	BorrowUSD       float64
	CollateralUSD   float64
	SupplyUSD       float64

	Selectors   []string
	TracedPools []common.Address
}

type Allocation struct {
	MarketID  string
	SupplyUSD float64
}

type Protocol struct {
	Address        common.Address
	Name           string
	Symbol         string
	Category       string
	TotalAssetsUSD float64
	Allocations    []Allocation
}

type MarketWithProtocols struct {
	Market    MorphoMarket
	Protocols []Protocol
}

// =============================================================
// GraphQL wire helpers
// =============================================================

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = FlexString(s)
		return nil
	}
	*f = FlexString(string(b))
	return nil
}

type gqlOracle struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

type gqlWarning struct {
	Type  string `json:"type"`
	Level string `json:"level"`
}

type gqlAsset struct {
	Address  string `json:"address"`
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Decimals int    `json:"decimals"`
}

type gqlMarketItem struct {
	MarketID        string       `json:"marketId"`
	LLTV            FlexString   `json:"lltv"`
	Listed          bool         `json:"listed"`
	Oracle          *gqlOracle   `json:"oracle"`
	Warnings        []gqlWarning `json:"warnings"`
	LoanAsset       gqlAsset     `json:"loanAsset"`
	CollateralAsset *gqlAsset    `json:"collateralAsset"`
	State           struct {
		BorrowAssetsUsd     float64 `json:"borrowAssetsUsd"`
		CollateralAssetsUsd float64 `json:"collateralAssetsUsd"`
		SupplyAssetsUsd     float64 `json:"supplyAssetsUsd"`
	} `json:"state"`
}

type gqlMarketsResponse struct {
	Data struct {
		Markets struct {
			Items []gqlMarketItem `json:"items"`
		} `json:"markets"`
	} `json:"data"`
}

type gqlAllocationItem struct {
	Market struct {
		MarketID string `json:"marketId"`
	} `json:"market"`
	SupplyAssetsUsd float64 `json:"supplyAssetsUsd"`
}

type gqlVaultState struct {
	TotalAssetsUsd float64             `json:"totalAssetsUsd"`
	Allocation     []gqlAllocationItem `json:"allocation"`
}

type gqlVaultItem struct {
	Address string        `json:"address"`
	Name    string        `json:"name"`
	Symbol  string        `json:"symbol"`
	State   gqlVaultState `json:"state"`
}

type gqlVaultsResponse struct {
	Data struct {
		Vaults struct {
			Items []gqlVaultItem `json:"items"`
		} `json:"vaults"`
	} `json:"data"`
}

// =============================================================
// Queries
// =============================================================

const morphoMarketsQuery = `query($first: Int!, $skip: Int!) {
  markets(
    first: $first
    skip: $skip
    orderBy: SupplyAssetsUsd
    orderDirection: Desc
    where: { chainId_in: [8453] }
  ) {
    items {
      marketId
      lltv
      listed
      oracle { address type }
      warnings { type level }
      loanAsset { address symbol name decimals }
      collateralAsset { address symbol name decimals }
      state {
        borrowAssetsUsd
        collateralAssetsUsd
        supplyAssetsUsd
      }
    }
  }
}`

const morphoVaultsQuery = `query($first: Int!, $skip: Int!) {
  vaults(
    first: $first
    skip: $skip
    orderBy: TotalAssetsUsd
    orderDirection: Desc
    where: { chainId_in: [8453] }
  ) {
    items {
      address
      name
      symbol
      state {
        totalAssetsUsd
        allocation {
          market { marketId }
          supplyAssetsUsd
        }
      }
    }
  }
}`

// =============================================================
// HTTP transport
// =============================================================

func postGraphQL(ctx context.Context, query string, vars map[string]any) ([]byte, error) {
	body, _ := json.Marshal(gqlRequest{Query: query, Variables: vars})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		MorphoGraphQLURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graphql HTTP %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

// =============================================================
// Market discovery (Morpho Blue)
// =============================================================

func DiscoverMarkets(ctx context.Context) ([]MorphoMarket, error) {
	var all []MorphoMarket
	for skip := 0; ; skip += 100 {
		if err := ctx.Err(); err != nil {
			return all, err
		}
		raw, err := postGraphQL(ctx, morphoMarketsQuery,
			map[string]any{"first": 100, "skip": skip})
		if err != nil {
			return nil, err
		}
		var parsed gqlMarketsResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("decode markets: %w", err)
		}
		items := parsed.Data.Markets.Items
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			if it.Oracle == nil || it.CollateralAsset == nil {
				continue
			}
			warnTypes := make([]string, 0, len(it.Warnings))
			for _, w := range it.Warnings {
				warnTypes = append(warnTypes, w.Type)
			}
			all = append(all, MorphoMarket{
				MarketID:   it.MarketID,
				Oracle:     common.HexToAddress(it.Oracle.Address),
				OracleType: it.Oracle.Type,
				Warnings:   warnTypes,
				Listed:     it.Listed,
				LLTV:       string(it.LLTV),
				LoanAsset: AssetInfo{
					Address:  common.HexToAddress(it.LoanAsset.Address),
					Symbol:   it.LoanAsset.Symbol,
					Name:     it.LoanAsset.Name,
					Decimals: uint8(it.LoanAsset.Decimals),
				},
				CollateralAsset: AssetInfo{
					Address:  common.HexToAddress(it.CollateralAsset.Address),
					Symbol:   it.CollateralAsset.Symbol,
					Name:     it.CollateralAsset.Name,
					Decimals: uint8(it.CollateralAsset.Decimals),
				},
				BorrowUSD:     it.State.BorrowAssetsUsd,
				CollateralUSD: it.State.CollateralAssetsUsd,
				SupplyUSD:     it.State.SupplyAssetsUsd,
			})
		}
		if len(items) < 100 {
			break
		}
	}
	return all, nil
}

// =============================================================
// MetaMorpho vault discovery (Morpho GraphQL)
// =============================================================

func DiscoverProtocols(ctx context.Context) ([]Protocol, error) {
	var all []Protocol
	for skip := 0; ; skip += 100 {
		if err := ctx.Err(); err != nil {
			return all, err
		}
		raw, err := postGraphQL(ctx, morphoVaultsQuery,
			map[string]any{"first": 100, "skip": skip})
		if err != nil {
			return nil, err
		}
		var parsed gqlVaultsResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("decode vaults: %w", err)
		}
		items := parsed.Data.Vaults.Items
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			allocs := make([]Allocation, 0, len(it.State.Allocation))
			for _, a := range it.State.Allocation {
				if a.Market.MarketID == "" {
					continue
				}
				allocs = append(allocs, Allocation{
					MarketID:  a.Market.MarketID,
					SupplyUSD: a.SupplyAssetsUsd,
				})
			}
			all = append(all, Protocol{
				Address:        common.HexToAddress(it.Address),
				Name:           it.Name,
				Symbol:         it.Symbol,
				Category:       classifyProtocol(it.Name, it.Symbol),
				TotalAssetsUSD: it.State.TotalAssetsUsd,
				Allocations:    allocs,
			})
		}
		if len(items) < 100 {
			break
		}
	}
	return all, nil
}

func classifyProtocol(name, symbol string) string {
	s := strings.ToLower(name + " " + symbol)
	switch {
	case strings.Contains(s, "delta"),
		strings.Contains(s, "neutral"),
		strings.Contains(s, "hedge"),
		strings.Contains(s, "basis"):
		return catDeltaNeutralVault
	case strings.Contains(s, "lever"),
		strings.Contains(s, "farm"),
		strings.Contains(s, "loop"),
		strings.Contains(s, "yield"):
		return catLeveragedYieldFarm
	case strings.Contains(s, "lp"),
		strings.Contains(s, "collateral"):
		return catLPCollateral
	case strings.Contains(s, "metamorpho"),
		strings.Contains(s, "vault"):
		return catERC4626YieldVault
	default:
		return catERC4626YieldVault
	}
}

// =============================================================
// DefiLlama discovery
// =============================================================

type defiLlamaProtocol struct {
	Name      string             `json:"name"`
	Slug      string             `json:"slug"`
	TVL       float64            `json:"tvl"`
	Category  string             `json:"category"`
	Chains    []string           `json:"chains"`
	ChainTvls map[string]float64 `json:"chainTvls"`
	URL       string             `json:"url"`
	Change1d  float64            `json:"change_1d"`
}

// DiscoverDefiLlamaProtocols fetches every DefiLlama protocol,
// filters to Base, target category, and Base-TVL >= minTVL, and
// attempts best-effort SQD address resolution.
func DiscoverDefiLlamaProtocols(ctx context.Context, minTVL float64) ([]Protocol, error) {
	raw, err := httpGet(ctx, DefiLlamaProtocolsURL)
	if err != nil {
		return nil, fmt.Errorf("defillama fetch: %w", err)
	}
	var all []defiLlamaProtocol
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("defillama decode: %w", err)
	}

	var out []Protocol
	for _, p := range all {
		if !containsString(p.Chains, DefiLlamaBaseChain) {
			continue
		}
		baseTVL, ok := p.ChainTvls[DefiLlamaBaseChain]
		if !ok {
			baseTVL = p.TVL
		}
		if baseTVL < minTVL {
			continue
		}
		if !TargetDefiLlamaCategories[p.Category] {
			continue
		}

		proto := Protocol{
			Name:           p.Name,
			Symbol:         p.Slug,
			Category:       mapDefiLlamaCategory(p.Category),
			TotalAssetsUSD: baseTVL,
		}

		// Best-effort address resolution. On failure, leave the
		// zero address; the protocol is still listed in the
		// universe and can be reported as "skipped" later.
		if addr, err := ResolveProtocolAddress(ctx, p.Name); err == nil {
			proto.Address = addr
		} else {
			fmt.Fprintf(os.Stderr,
				"scanner: sqd resolve %q failed: %v\n", p.Name, err)
		}

		out = append(out, proto)
	}
	return out, nil
}

// mapDefiLlamaCategory converts a DefiLlama category to the
// scanner's internal category labels.
func mapDefiLlamaCategory(dl string) string {
	switch dl {
	case "Leveraged Farming", "Yield Aggregator", "Yield":
		return catLeveragedYieldFarm
	case "Delta Neutral":
		return catDeltaNeutralVault
	case "LP Collateral", "Lending":
		return catLPCollateral
	default:
		return catUnknown
	}
}

// =============================================================
// SQD Portal: name -> address resolution
// =============================================================

// sqdRequest is the payload sent to the SQD Portal resolve endpoint.
// The exact field names depend on the deployed Portal; if the
// endpoint returns nothing useful, we log and continue with the
// zero address so the pipeline never aborts.
type sqdRequest struct {
	Query   string `json:"query"`
	Network string `json:"network"`
	Kind    string `json:"kind"`
	Limit   int    `json:"limit"`
}

type sqdMatch struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	ChainID int    `json:"chainId"`
}

type sqdResponse struct {
	Matches []sqdMatch `json:"matches"`
}

// ResolveProtocolAddress returns the primary Base contract address
// for the given protocol name. On any failure (network, no match,
// non-Base result) it returns the zero address and an error.
func ResolveProtocolAddress(ctx context.Context, name string) (common.Address, error) {
	body, _ := json.Marshal(sqdRequest{
		Query:   name,
		Network: "base-mainnet",
		Kind:    "protocol",
		Limit:   5,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		SQDPortalURL+"/resolve", bytes.NewReader(body))
	if err != nil {
		return common.Address{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return common.Address{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return common.Address{}, fmt.Errorf("sqd HTTP %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var parsed sqdResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return common.Address{}, err
	}
	for _, m := range parsed.Matches {
		if m.Address == "" {
			continue
		}
		if m.ChainID != 0 && m.ChainID != 8453 {
			continue
		}
		return common.HexToAddress(m.Address), nil
	}
	return common.Address{}, fmt.Errorf("sqd: no Base match for %q", name)
}

// =============================================================
// Combined discovery
// =============================================================

// DiscoverAllProtocols merges Morpho MetaMorpho vaults and the
// DefiLlama protocol universe. Deduplicates by lowercase name.
// Non-fatal failures are logged and the other path's output is
// still returned.
func DiscoverAllProtocols(ctx context.Context, minTVL float64) ([]Protocol, error) {
	var merged []Protocol

	morphoProtos, err := DiscoverProtocols(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: morpho vaults discovery failed: %v\n", err)
	} else {
		merged = append(merged, morphoProtos...)
	}

	dlProtos, err := DiscoverDefiLlamaProtocols(ctx, minTVL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: defillama discovery failed: %v\n", err)
	} else {
		merged = append(merged, dlProtos...)
	}

	if len(merged) == 0 {
		return nil, fmt.Errorf("all discovery paths failed")
	}

	seen := make(map[string]bool)
	var out []Protocol
	for _, p := range merged {
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if key == "" {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out, nil
}

// =============================================================
// Join
// =============================================================

// BuildMarketProtocolIndex joins protocols to markets by allocation
// market ID. Only markets that have at least one matching protocol
// are emitted.
func BuildMarketProtocolIndex(
	markets []MorphoMarket,
	protocols []Protocol,
) []MarketWithProtocols {

	idx := make(map[string][]Protocol)
	for _, p := range protocols {
		for _, a := range p.Allocations {
			key := normalizeMarketID(a.MarketID)
			if key == "" {
				continue
			}
			idx[key] = append(idx[key], p)
		}
	}

	var out []MarketWithProtocols
	for _, m := range markets {
		key := normalizeMarketID(m.MarketID)
		ps := idx[key]
		if len(ps) == 0 {
			continue
		}
		out = append(out, MarketWithProtocols{
			Market:    m,
			Protocols: ps,
		})
	}
	return out
}

// AttachProtocolsToMarkets emits an entry for every market, using
// the empty slice when no protocols are matched. This keeps
// vulnerable oracles with no known protocol exposure in the scan,
// so the report distinguishes "no protocol found" from "no
// vulnerability found."
func AttachProtocolsToMarkets(
	markets []MorphoMarket,
	protocols []Protocol,
) []MarketWithProtocols {

	idx := make(map[string][]Protocol)
	for _, p := range protocols {
		for _, a := range p.Allocations {
			key := normalizeMarketID(a.MarketID)
			if key == "" {
				continue
			}
			idx[key] = append(idx[key], p)
		}
	}

	out := make([]MarketWithProtocols, 0, len(markets))
	for _, m := range markets {
		key := normalizeMarketID(m.MarketID)
		out = append(out, MarketWithProtocols{
			Market:    m,
			Protocols: idx[key],
		})
	}
	return out
}

func normalizeMarketID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	return s
}

// =============================================================
// Helpers
// =============================================================

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// =============================================================
// Dedupe helpers
// =============================================================

func UniqueOracles(markets []MorphoMarket) []common.Address {
	seen := make(map[common.Address]struct{})
	var out []common.Address
	for _, m := range markets {
		if m.Oracle == (common.Address{}) {
			continue
		}
		if _, ok := seen[m.Oracle]; ok {
			continue
		}
		seen[m.Oracle] = struct{}{}
		out = append(out, m.Oracle)
	}
	return out
}

func UniqueProtocols(ps []Protocol) []common.Address {
	seen := make(map[common.Address]struct{})
	var out []common.Address
	for _, p := range ps {
		if p.Address == (common.Address{}) {
			continue
		}
		if _, ok := seen[p.Address]; ok {
			continue
		}
		seen[p.Address] = struct{}{}
		out = append(out, p.Address)
	}
	return out
}
