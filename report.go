package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// Report types
// =============================================================

type FlagReport struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Snippet     string   `json:"snippet"`
	LineStart   int      `json:"line_start"`
	LineEnd     int      `json:"line_end"`
	Suppressors []string `json:"suppressors,omitempty"`
	LLMVerdict  string   `json:"llm_verdict"`
}

type FindingReport struct {
	Rank       int          `json:"rank"`
	Protocol   string       `json:"protocol"`
	Slug       string       `json:"slug"`
	Category   string       `json:"category"`
	TVLUSD     float64      `json:"tvl_usd"`
	Address    string       `json:"address"`
	Chain      string       `json:"chain"`
	Flags      []FlagReport `json:"flags"`
	Summary    string       `json:"summary"`
}

type RunMetadata struct {
	SchemaVersion    string `json:"schema_version"`
	ChainID          int64  `json:"chain_id"`
	BlockNumber      uint64 `json:"block_number"`
	Timestamp        string `json:"timestamp"`
	CategoryKeyword  string `json:"category_keyword"`
	ProtocolsFound   int    `json:"protocols_found"`
	ProtocolsScanned int    `json:"protocols_scanned"`
	ProtocolsSkipped int    `json:"protocols_skipped"`
	TotalFlags       int    `json:"total_flags"`
	VulnerableCount  int    `json:"vulnerable_count"`
}

type SkippedProtocol struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Reason string `json:"reason"`
}

type Report struct {
	Metadata  RunMetadata      `json:"metadata"`
	Findings  []FindingReport  `json:"findings"`
	Skipped   []SkippedProtocol `json:"skipped"`
}

// =============================================================
// Build report
// =============================================================

func BuildReport(
	meta RunMetadata,
	findings []FindingReport,
	skipped []SkippedProtocol,
) *Report {
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].TVLUSD > findings[j].TVLUSD
	})
	for i := range findings {
		findings[i].Rank = i + 1
	}

	meta.SchemaVersion = "7.0"
	meta.Timestamp = time.Now().UTC().Format(time.RFC3339)
	meta.VulnerableCount = len(findings)
	meta.ProtocolsSkipped = len(skipped)

	return &Report{
		Metadata: meta,
		Findings: findings,
		Skipped:  skipped,
	}
}

// =============================================================
// Rendering
// =============================================================

func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "=== BASE PROTOCOL SPOT-AMM EXPOSURE SCAN (v7.0) ===\n")
	fmt.Fprintf(w, "Category: %s   Block: %d   %s\n",
		r.Metadata.CategoryKeyword, r.Metadata.BlockNumber, r.Metadata.Timestamp)
	fmt.Fprintf(w, "Protocols found: %d   scanned: %d   skipped: %d\n",
		r.Metadata.ProtocolsFound, r.Metadata.ProtocolsScanned, r.Metadata.ProtocolsSkipped)
	fmt.Fprintf(w, "Total flags: %d   vulnerable: %d\n\n",
		r.Metadata.TotalFlags, r.Metadata.VulnerableCount)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "(no vulnerable protocols)")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%d] %s  [%s]  tvl=$%.0f\n", f.Rank, f.Protocol, f.Category, f.TVLUSD)
		fmt.Fprintf(w, "     Address: %s\n", f.Address)
		fmt.Fprintf(w, "     Flags:   %d\n", len(f.Flags))
		for _, fl := range f.Flags {
			fmt.Fprintf(w, "       - %s [%s] LLM=%s  lines %d-%d\n",
				fl.RuleID, fl.Severity, fl.LLMVerdict, fl.LineStart, fl.LineEnd)
		}
	}

	if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "\n--- SKIPPED (%d) ---\n", len(r.Skipped))
		for _, s := range r.Skipped {
			fmt.Fprintf(w, "  %-30s  %s\n", s.Name, s.Reason)
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
