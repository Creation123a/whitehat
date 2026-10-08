package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ---------- Types ----------

type MarketReport struct {
	Rank              int      `json:"rank"`
	MarketID          string   `json:"market_id"`
	Oracle            string   `json:"oracle"`
	OracleType        string   `json:"oracle_type"`
	Warnings          []string `json:"warnings,omitempty"`
	Listed            bool     `json:"listed"`
	LoanSymbol        string   `json:"loan_symbol"`
	LoanAddress       string   `json:"loan_address"`
	CollateralSymbol  string   `json:"collateral_symbol"`
	CollateralAddress string   `json:"collateral_address"`
	LLTV              string   `json:"lltv"`
	SupplyUSD         float64  `json:"supply_usd"`
	BorrowUSD         float64  `json:"borrow_usd"`
	CollateralUSD     float64  `json:"collateral_usd"`
	PoolAddress       string   `json:"pool_address"`
	PoolKind          string   `json:"pool_kind"`
	PriceBefore       string   `json:"price_before"`
	PriceAfter        string   `json:"price_after"`
	DeltaPct          float64  `json:"delta_pct"`
	Selectors         []string `json:"selectors"`
	Evidence          string   `json:"evidence"`
	Remediation       string   `json:"remediation"`
}

type OperationalProperty struct {
	ID           string `json:"id"`
	Property     string `json:"property"`
	Present      bool   `json:"present"`
	Measures     string `json:"measures"`
	AuditFraming string `json:"audit_framing,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	Source       string `json:"source"`
	GateEligible bool   `json:"gate_eligible"`
}

type RunMetadata struct {
	SchemaVersion        string `json:"schema_version"`
	ChainID              int64  `json:"chain_id"`
	BlockNumber          uint64 `json:"block_number"`
	Timestamp            string `json:"timestamp"`
	MarketsFromAPI       int    `json:"markets_from_api"`
	SuspiciousOracles    int    `json:"suspicious_oracles"`
	UniqueOracles        int    `json:"unique_oracles"`
	MarketsShortlisted   int    `json:"markets_shortlisted"`
	ConfirmedCount       int    `json:"confirmed_count"`
}

type Report struct {
	Metadata              RunMetadata           `json:"metadata"`
	ConfirmedMarkets      []MarketReport        `json:"confirmed_markets"`
	OperationalProperties []OperationalProperty `json:"operational_properties"`
}

// ---------- Entry point ----------

func BuildReport(
	ctx context.Context,
	client *ethclient.Client,
	meta RunMetadata,
	confirmed []ConfirmedMarket,
	ops []OperationalProperty,
) (*Report, error) {

	reports := make([]MarketReport, 0, len(confirmed))
	for _, cm := range confirmed {
		reports = append(reports, toReport(cm))
	}

	// Sort by supply USD descending — TVL is a ranking, not a filter.
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].SupplyUSD > reports[j].SupplyUSD
	})
	for i := range reports {
		reports[i].Rank = i + 1
	}

	meta.SchemaVersion = "3.0"
	meta.Timestamp = time.Now().UTC().Format(time.RFC3339)

	return &Report{
		Metadata:              meta,
		ConfirmedMarkets:      reports,
		OperationalProperties: ops,
	}, nil
}

func toReport(cm ConfirmedMarket) MarketReport {
	m := cm.Market
	return MarketReport{
		MarketID:          m.MarketID,
		Oracle:            m.Oracle.Hex(),
		OracleType:        m.OracleType,
		Warnings:          m.Warnings,
		Listed:            m.Listed,
		LoanSymbol:        m.LoanAsset.Symbol,
		LoanAddress:       m.LoanAsset.Address.Hex(),
		CollateralSymbol:  m.CollateralAsset.Symbol,
		CollateralAddress: m.CollateralAsset.Address.Hex(),
		LLTV:              m.LLTV,
		SupplyUSD:         m.SupplyUSD,
		BorrowUSD:         m.BorrowUSD,
		CollateralUSD:     m.CollateralUSD,
		PoolAddress:       cm.Pool.Hex(),
		PoolKind:          cm.PoolKind,
		PriceBefore:       cm.PriceBefore.String(),
		PriceAfter:        cm.PriceAfter.String(),
		DeltaPct:          cm.DeltaPct,
		Selectors:         m.Selectors,
		Evidence:          cm.Evidence,
		Remediation: fmt.Sprintf(
			"replace oracle at %s with a TWAP or Chainlink composite; AMM pool %s is manipulable",
			m.Oracle.Hex(), cm.Pool.Hex()),
	}
}

// ---------- Low-level ABI helpers (used by simulation.go) ----------

func callMsgData(to common.Address, selector []byte, args ...[]byte) ethereum.CallMsg {
	data := make([]byte, 0, 4+32*len(args))
	data = append(data, selector...)
	for _, a := range args {
		data = append(data, a...)
	}
	return ethereum.CallMsg{To: &to, Data: data}
}

func callBig(
	ctx context.Context, client *ethclient.Client,
	to common.Address, selector []byte,
) (*big.Int, error) {
	raw, err := client.CallContract(ctx, callMsgData(to, selector), nil)
	if err != nil {
		return nil, err
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("short response")
	}
	return new(big.Int).SetBytes(raw[:32]), nil
}

// ---------- Rendering ----------

func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "=== MORPHO SPOT-AMM ORACLE SCAN ===\n")
	fmt.Fprintf(w, "Chain %d  Block %d  %s\n",
		r.Metadata.ChainID, r.Metadata.BlockNumber, r.Metadata.Timestamp)
	fmt.Fprintf(w, "API markets: %d   suspicious oracles: %d   unique: %d   shortlisted: %d   confirmed: %d\n\n",
		r.Metadata.MarketsFromAPI, r.Metadata.SuspiciousOracles,
		r.Metadata.UniqueOracles, r.Metadata.MarketsShortlisted,
		r.Metadata.ConfirmedCount)

	fmt.Fprintln(w, "--- CONFIRMED MARKETS (sorted by supply USD) ---")
	for _, m := range r.ConfirmedMarkets {
		fmt.Fprintf(w, "\n[%d] %s / %s   supply=$%.0f  borrow=$%.0f\n",
			m.Rank, m.CollateralSymbol, m.LoanSymbol, m.SupplyUSD, m.BorrowUSD)
		fmt.Fprintf(w, "     Market:     %s\n", m.MarketID)
		fmt.Fprintf(w, "     Oracle:     %s  (%s, listed=%v)\n",
			m.Oracle, m.OracleType, m.Listed)
		if len(m.Warnings) > 0 {
			fmt.Fprintf(w, "     Warnings:   %s\n", strings.Join(m.Warnings, ", "))
		}
		fmt.Fprintf(w, "     LLTV:       %s\n", m.LLTV)
		fmt.Fprintf(w, "     Pool:       %s (%s)\n", m.PoolAddress, m.PoolKind)
		fmt.Fprintf(w, "     Selectors:  %s\n", strings.Join(m.Selectors, ", "))
		fmt.Fprintf(w, "     Delta:      %.2f%%\n", m.DeltaPct)
		fmt.Fprintf(w, "     Evidence:   %s\n", m.Evidence)
		fmt.Fprintf(w, "     Remediate:  %s\n", m.Remediation)
	}

	if len(r.OperationalProperties) > 0 {
		fmt.Fprintln(w, "\n--- OPERATIONAL PROPERTIES (non-gate) ---")
		for _, o := range r.OperationalProperties {
			state := "absent"
			if o.Present {
				state = "present"
			}
			fmt.Fprintf(w, "\n%s  %-28s [%s]\n", o.ID, o.Property, state)
			fmt.Fprintf(w, "     Measures:  %s\n", o.Measures)
			if o.AuditFraming != "" {
				fmt.Fprintf(w, "     Framing:   %s\n", o.AuditFraming)
			}
			if o.Remediation != "" {
				fmt.Fprintf(w, "     Remediate: %s\n", o.Remediation)
			}
			fmt.Fprintf(w, "     Source:    %s (gate_eligible=false)\n", o.Source)
		}
	}
}

func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ---------- O-1..O-4 seed ----------

func DefaultOperationalProperties(present map[string]bool) []OperationalProperty {
	rows := []OperationalProperty{
		{
			ID: "O-1", Property: "Public RPC only",
			Measures:     "Monitoring posture",
			AuditFraming: "No evidence of monitoring infrastructure; mean time to detection may exceed block finality (soft inference)",
			Remediation:  "Deploy dedicated alerting",
			Source:       "declared",
		},
		{ID: "O-2", Property: "Anonymous team", Measures: "Attribution difficulty", Source: "declared"},
		{ID: "O-3", Property: "No legal entity", Measures: "Post-incident recovery capability", Source: "declared"},
		{ID: "O-4", Property: "Tracking obsolete", Measures: "Attribution difficulty", Source: "declared"},
	}
	for i := range rows {
		if v, ok := present[rows[i].ID]; ok {
			rows[i].Present = v
		}
		rows[i].GateEligible = false
	}
	return rows
}

// ---------- CLI helper ----------

func WriteReport(path string, format string, r *Report) int {
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
}
