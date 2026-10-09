package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ProtocolReport struct {
	Address        string  `json:"address"`
	Name           string  `json:"name"`
	Symbol         string  `json:"symbol"`
	Category       string  `json:"category"`
	TotalAssetsUSD float64 `json:"total_assets_usd"`
	ExposureUSD    float64 `json:"exposure_usd"`
}

type FindingReport struct {
	Rank             int              `json:"rank"`
	MarketID         string           `json:"market_id"`
	Oracle           string           `json:"oracle"`
	OracleType       string           `json:"oracle_type"`
	Warnings         []string         `json:"warnings,omitempty"`
	LoanSymbol       string           `json:"loan_symbol"`
	CollateralSymbol string           `json:"collateral_symbol"`
	LLTV             string           `json:"lltv"`
	SupplyUSD        float64          `json:"supply_usd"`
	BorrowUSD        float64          `json:"borrow_usd"`
	PoolAddress      string           `json:"pool_address"`
	PoolKind         string           `json:"pool_kind"`
	PriceBefore      string           `json:"price_before"`
	PriceAfter       string           `json:"price_after"`
	DeltaPct         float64          `json:"delta_pct"`
	Selectors        []string         `json:"selectors,omitempty"`
	Protocols        []ProtocolReport `json:"protocols"`
	Evidence         string           `json:"evidence"`
	Remediation      string           `json:"remediation"`
}

type SuspectedReport struct {
	Rank             int              `json:"rank"`
	MarketID         string           `json:"market_id"`
	Oracle           string           `json:"oracle"`
	OracleType       string           `json:"oracle_type"`
	LoanSymbol       string           `json:"loan_symbol"`
	CollateralSymbol string           `json:"collateral_symbol"`
	SupplyUSD        float64          `json:"supply_usd"`
	BorrowUSD        float64          `json:"borrow_usd"`
	Reason           string           `json:"reason"`
	Protocols        []ProtocolReport `json:"protocols"`
}

type RunMetadata struct {
	SchemaVersion        string `json:"schema_version"`
	ChainID              int64  `json:"chain_id"`
	BlockNumber          uint64 `json:"block_number"`
	Timestamp            string `json:"timestamp"`
	MarketsFromAPI       int    `json:"markets_from_api"`
	ProtocolsFromAPI     int    `json:"protocols_from_api"`
	MarketsAfterCountFlt int    `json:"markets_after_protocol_count_filter"`
	MarketsAfterTVLFlt   int    `json:"markets_after_tvl_filter"`
	MarketsVulnerable    int    `json:"markets_vulnerable"`
	ConfirmedCount       int    `json:"confirmed_count"`
	SuspectedCount       int    `json:"suspected_count"`
}

type Report struct {
	Metadata  RunMetadata     `json:"metadata"`
	Confirmed []FindingReport `json:"confirmed"`
	Suspected []SuspectedReport `json:"suspected"`
}

// sameMarketID compares two market IDs using the same normalization
// used by the join. Must be used everywhere MarketIDs are compared.
func sameMarketID(a, b string) bool {
	return normalizeMarketID(a) == normalizeMarketID(b)
}

func BuildReport(
	ctx context.Context,
	client *ethclient.Client,
	meta RunMetadata,
	confirmed []ConfirmedMarket,
	suspected []SuspectedMarket,
) (*Report, error) {

	cr := make([]FindingReport, 0, len(confirmed))
	for _, c := range confirmed {
		cr = append(cr, toFindingReport(c))
	}
	sort.SliceStable(cr, func(i, j int) bool {
		return cr[i].SupplyUSD > cr[j].SupplyUSD
	})
	for i := range cr {
		cr[i].Rank = i + 1
	}

	sr := make([]SuspectedReport, 0, len(suspected))
	for _, s := range suspected {
		sr = append(sr, toSuspectedReport(s))
	}
	for i := range sr {
		sr[i].Rank = i + 1
	}

	meta.SchemaVersion = "6.0"
	meta.Timestamp = time.Now().UTC().Format(time.RFC3339)

	return &Report{
		Metadata:  meta,
		Confirmed: cr,
		Suspected: sr,
	}, nil
}

func toFindingReport(c ConfirmedMarket) FindingReport {
	protocols := make([]ProtocolReport, 0, len(c.Protocols))
	for _, p := range c.Protocols {
		var exposure float64
		for _, a := range p.Allocations {
			if sameMarketID(a.MarketID, c.Market.MarketID) {
				exposure += a.SupplyUSD
			}
		}
		protocols = append(protocols, ProtocolReport{
			Address:        p.Address.Hex(),
			Name:           p.Name,
			Symbol:         p.Symbol,
			Category:       p.Category,
			TotalAssetsUSD: p.TotalAssetsUSD,
			ExposureUSD:    exposure,
		})
	}
	return FindingReport{
		MarketID:         c.Market.MarketID,
		Oracle:           c.Market.Oracle.Hex(),
		OracleType:       c.Market.OracleType,
		Warnings:         c.Market.Warnings,
		LoanSymbol:       c.Market.LoanAsset.Symbol,
		CollateralSymbol: c.Market.CollateralAsset.Symbol,
		LLTV:             c.Market.LLTV,
		SupplyUSD:        c.Market.SupplyUSD,
		BorrowUSD:        c.Market.BorrowUSD,
		PoolAddress:      c.Pool.Hex(),
		PoolKind:         c.PoolKind,
		PriceBefore:      c.PriceBefore.String(),
		PriceAfter:       c.PriceAfter.String(),
		DeltaPct:         c.DeltaPct,
		Selectors:        c.Market.Selectors,
		Protocols:        protocols,
		Evidence:         c.Evidence,
		Remediation: fmt.Sprintf(
			"oracle %s reads spot AMM state from pool %s; "+
				"all protocols supplying to this market are exposed",
			c.Market.Oracle.Hex(), c.Pool.Hex()),
	}
}

func toSuspectedReport(s SuspectedMarket) SuspectedReport {
	protocols := make([]ProtocolReport, 0, len(s.Protocols))
	for _, p := range s.Protocols {
		var exposure float64
		for _, a := range p.Allocations {
			if sameMarketID(a.MarketID, s.Market.MarketID) {
				exposure += a.SupplyUSD
			}
		}
		protocols = append(protocols, ProtocolReport{
			Address:        p.Address.Hex(),
			Name:           p.Name,
			Symbol:         p.Symbol,
			Category:       p.Category,
			TotalAssetsUSD: p.TotalAssetsUSD,
			ExposureUSD:    exposure,
		})
	}
	return SuspectedReport{
		MarketID:         s.Market.MarketID,
		Oracle:           s.Market.Oracle.Hex(),
		OracleType:       s.Market.OracleType,
		LoanSymbol:       s.Market.LoanAsset.Symbol,
		CollateralSymbol: s.Market.CollateralAsset.Symbol,
		SupplyUSD:        s.Market.SupplyUSD,
		BorrowUSD:        s.Market.BorrowUSD,
		Reason:           s.Reason,
		Protocols:        protocols,
	}
}

func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "=== BASE NETWORK SPOT-AMM EXPOSURE SCAN (v6.0) ===\n")
	fmt.Fprintf(w, "Chain %d  Block %d  %s\n",
		r.Metadata.ChainID, r.Metadata.BlockNumber, r.Metadata.Timestamp)
	fmt.Fprintf(w, "Markets from API: %d   Protocols discovered: %d\n",
		r.Metadata.MarketsFromAPI, r.Metadata.ProtocolsFromAPI)
	fmt.Fprintf(w, "Vulnerable markets (triage): %d   after protocol filter: %d\n",
		r.Metadata.MarketsAfterCountFlt, r.Metadata.MarketsAfterTVLFlt)
	fmt.Fprintf(w, "Confirmed: %d   Suspected: %d\n\n",
		r.Metadata.ConfirmedCount, r.Metadata.SuspectedCount)

	fmt.Fprintln(w, "--- CONFIRMED (vulnerable oracles exposing one or more protocols) ---")
	if len(r.Confirmed) == 0 {
		fmt.Fprintln(w, "(none)")
	}
	for _, f := range r.Confirmed {
		fmt.Fprintf(w, "\n[%d] %s / %s   supply=$%.0f borrow=$%.0f   delta=%.2f%%\n",
			f.Rank, f.CollateralSymbol, f.LoanSymbol, f.SupplyUSD, f.BorrowUSD, f.DeltaPct)
		fmt.Fprintf(w, "     Market:      %s\n", f.MarketID)
		fmt.Fprintf(w, "     Oracle:      %s (%s)\n", f.Oracle, f.OracleType)
		if len(f.Warnings) > 0 {
			fmt.Fprintf(w, "     Warnings:    %s\n", strings.Join(f.Warnings, ", "))
		}
		fmt.Fprintf(w, "     Pool:        %s (%s)\n", f.PoolAddress, f.PoolKind)
		fmt.Fprintf(w, "     Price:       %s -> %s\n", f.PriceBefore, f.PriceAfter)
		if len(f.Selectors) > 0 {
			fmt.Fprintf(w, "     Selectors:   %s\n", strings.Join(f.Selectors, ", "))
		}
		fmt.Fprintf(w, "     Protocols exposed (%d):\n", len(f.Protocols))
		for _, p := range f.Protocols {
			fmt.Fprintf(w, "       - %-28s [%s] tvl=$%.0f  exposure=$%.0f  %s\n",
				p.Name, p.Category, p.TotalAssetsUSD, p.ExposureUSD, p.Address)
		}
		fmt.Fprintf(w, "     Remediate:   %s\n", f.Remediation)
	}

	if len(r.Suspected) > 0 {
		fmt.Fprintf(w, "\n--- SUSPECTED (%d) ---\n", len(r.Suspected))
		for _, s := range r.Suspected {
			fmt.Fprintf(w, "\n[%d] %s / %s   supply=$%.0f\n",
				s.Rank, s.CollateralSymbol, s.LoanSymbol, s.SupplyUSD)
			fmt.Fprintf(w, "     Oracle:      %s (%s)\n", s.Oracle, s.OracleType)
			fmt.Fprintf(w, "     Reason:      %s\n", s.Reason)
			for _, p := range s.Protocols {
				fmt.Fprintf(w, "       - %-28s [%s] exposure=$%.0f\n",
					p.Name, p.Category, p.ExposureUSD)
			}
		}
	}
}

func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteReport(path, format string, r *Report) int {
	var w io.Writer = os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: cannot create %s: %v\n", path, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if format == "json" {
		if err := RenderJSON(w, r); err != nil {
			fmt.Fprintf(os.Stderr, "report: json encode: %v\n", err)
			return 1
		}
	} else {
		RenderText(w, r)
	}
	return 0
}

var _ = common.Address{}
