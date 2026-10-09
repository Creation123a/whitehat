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

// AssetInfo describes a loan or collateral token.
type AssetInfo struct {
	Address  common.Address
	Symbol   string
	Name     string
	Decimals uint8
}

// MorphoMarket is one market row.
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

	// Populated by TriageOracles in analysis.go.
	Selectors   []string
	TracedPools []common.Address
}

// ---------- Baseline assets (informational only) ----------
//
// These are no longer used as a filter — the oracle is the object
// of interest, not the collateral. Kept for reference and future
// use by report classification.
var baselineAssets = map[common.Address]bool{
	common.HexToAddress("0x4200000000000000000000000000000000000006"): true, // WETH
	common.HexToAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): true, // USDC
	common.HexToAddress("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): true, // USDbC
	common.HexToAddress("0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22"): true, // cbETH
	common.HexToAddress("0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452"): true, // wstETH
	common.HexToAddress("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"): true, // cbBTC
	common.HexToAddress("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"): true, // DAI
	common.HexToAddress("0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"): true, // EURC
}

// wrapperPatterns kept for future classification; not used as a
// discovery filter anymore.
var wrapperPatterns = []string{
	"lp", "share", "vault", "slip", "lrt",
}

// ---------- GraphQL wire types ----------

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

// Discover pulls every Morpho Blue market on Base. No collateral
// filter is applied — the oracle is the object of interest and a
// baseline collateral does not make an oracle safe.
func Discover(ctx context.Context) ([]MorphoMarket, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var all []MorphoMarket

	for skip := 0; ; skip += 100 {
		if err := ctx.Err(); err != nil {
			return all, err
		}
		reqBody, _ := json.Marshal(gqlRequest{
			Query: morphoMarketsQuery,
			Variables: map[string]any{
				"first": 100,
				"skip":  skip,
			},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			MorphoGraphQLURL, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("morpho api: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("morpho api: HTTP %d: %s",
				resp.StatusCode, string(body))
		}

		var parsed gqlMarketsResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("morpho api decode: %w", err)
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

			m := MorphoMarket{
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
			}
			all = append(all, m)
		}

		if len(items) < 100 {
			break
		}
	}
	return all, nil
}

// isSuspiciousCollateral is retained for future classification. It
// is no longer called during discovery.
func isSuspiciousCollateral(addr common.Address, symbol, name string) bool {
	s := strings.ToLower(symbol + " " + name)
	for _, p := range wrapperPatterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return !baselineAssets[addr]
}

// UniqueCollaterals returns deduplicated collateral addresses.
func UniqueCollaterals(markets []MorphoMarket) []common.Address {
	seen := make(map[common.Address]struct{})
	var out []common.Address
	for _, m := range markets {
		if m.CollateralAsset.Address == (common.Address{}) {
			continue
		}
		if _, ok := seen[m.CollateralAsset.Address]; ok {
			continue
		}
		seen[m.CollateralAsset.Address] = struct{}{}
		out = append(out, m.CollateralAsset.Address)
	}
	return out
}

// UniqueOracles returns deduplicated oracle addresses.
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
