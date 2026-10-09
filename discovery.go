package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// ---------- Market wire types ----------

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

// ---------- V1 vault wire types ----------
//
// V1 (MetaMorpho) schema:
//   - state.totalAssetsUsd
//   - state.allocation[] with market { marketId } and supplyAssetsUsd
//
// The `uniqueKey` field name belongs to V2 / Midnight, not V1.

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

// morphoVaultsQuery targets the V1 `vaults` root. State is nested
// under `state`; allocation items reference markets by `marketId`.
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

// =============================================================
// Market discovery
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
// Protocol discovery
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
// Join
// =============================================================

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

func normalizeMarketID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	return s
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
