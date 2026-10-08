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
	Decimals uint8
}

// MorphoMarket is one market row, enriched with the API's oracle
// classification and warnings. Populated by Discover.
type MorphoMarket struct {
	MarketID        string
	Oracle          common.Address
	OracleType      string   // "Chainlink" | "ChainlinkV2" | "Custom"
	Warnings        []string // warning type strings
	Listed          bool
	LoanAsset       AssetInfo
	CollateralAsset AssetInfo
	LLTV            string
	BorrowUSD       float64
	CollateralUSD   float64
	SupplyUSD       float64

	// Populated by TriageOracles in analysis.go.
	Selectors []string
}

// ---------- GraphQL wire types ----------

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
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
	Decimals int    `json:"decimals"`
}

type gqlMarketItem struct {
	MarketID        string      `json:"marketId"`
	LLTV            string      `json:"lltv"`
	Listed          bool        `json:"listed"`
	Oracle          *gqlOracle  `json:"oracle"`
	Warnings        []gqlWarning `json:"warnings"`
	LoanAsset       gqlAsset    `json:"loanAsset"`
	CollateralAsset *gqlAsset   `json:"collateralAsset"`
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
      loanAsset { address symbol decimals }
      collateralAsset { address symbol decimals }
      state {
        borrowAssetsUsd
        collateralAssetsUsd
        supplyAssetsUsd
      }
    }
  }
}`

// Discover pulls every Morpho Blue market on Base, keeps only those
// whose oracle is Custom or carries a warning flag, and returns them.
// No TVL filter — TVL is a sort key in the report.
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
			// Skip markets without oracle or collateral (idle markets).
			if it.Oracle == nil || it.CollateralAsset == nil {
				continue
			}

			// Primary filter — keep only suspicious oracles.
			if !isSuspiciousOracle(it.Oracle.Type, it.Warnings) {
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
				LLTV:       it.LLTV,
				LoanAsset: AssetInfo{
					Address:  common.HexToAddress(it.LoanAsset.Address),
					Symbol:   it.LoanAsset.Symbol,
					Decimals: uint8(it.LoanAsset.Decimals),
				},
				CollateralAsset: AssetInfo{
					Address:  common.HexToAddress(it.CollateralAsset.Address),
					Symbol:   it.CollateralAsset.Symbol,
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

// isSuspiciousOracle returns true when the oracle is not a
// Chainlink-composed reference implementation, or when Morpho's own
// risk engine flags it.
//
// VERIFY the exact warning type strings against the live API before
// trusting this filter. If the API uses different casing or separators,
// no market will match and the pipeline will return zero candidates.
// isSuspiciousOracle returns true when the oracle is not a
// Chainlink-composed reference implementation, or when Morpho's own
// risk engine flags it.
//
// Matching is case- and separator-insensitive so it tolerates any of:
//   "unrecognized_oracle", "UNRECOGNIZED_ORACLE", "oracle-unrecognized"
//   "hardcoded_oracle_feed", "HARDCODED_FEED", "hardcodedFeed"
// Substring matching is used because the exact API taxonomy may change
// without notice. If the API introduces a new suspicious warning that
// contains "unrecognized" / "hardcoded" / "incompatible", it will be
// caught automatically.
// isSuspiciousOracle returns true when the oracle is not Morpho's
// recognized Chainlink reference implementation, or when the API flags
// a price derivation problem on an otherwise-Chainlink oracle.
//
// Verified against the live API on 2026-10-08. Actual taxonomies:
//   oracle.type:  "ChainlinkOracleV2", "Unknown"
//   warnings:     "not_whitelisted", "unrecognized_collateral_asset",
//                 "sustained_low_liquidity", "bad_debt_unrealized",
//                 "oracle_price_derivation"
func isSuspiciousOracle(oracleType string, warnings []gqlWarning) bool {
	// Anything that isn't the reference oracle is worth bytecode triage.
	if !strings.EqualFold(oracleType, "ChainlinkOracleV2") {
		return true
	}
	// Chainlink oracle but the derived price doesn't match USD — flag.
	// This is the case at market 0xff0f2bd5... in the diagnostic run.
	for _, w := range warnings {
		if strings.EqualFold(w.Type, "oracle_price_derivation") {
			return true
		}
	}
	return false
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
