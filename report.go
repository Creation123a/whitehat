package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type FlagReport struct {
	RuleID          string   `json:"rule_id"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Snippet         string   `json:"snippet"`
	LineStart       int      `json:"line_start"`
	LineEnd         int      `json:"line_end"`
	Suppressors     []string `json:"suppressors,omitempty"`
	LLMVerdict      string   `json:"llm_verdict"`
	ContractAddress string   `json:"contract_address"`
	ContractRole    string   `json:"contract_role"`
}

type FindingReport struct {
	Rank     int          `json:"rank"`
	Protocol string       `json:"protocol"`
	Slug     string       `json:"slug"`
	Category string       `json:"category"`
	TVLUSD   float64      `json:"tvl_usd"`
	Flags    []FlagReport `json:"flags"`
}

// LeadReport captures bytecode-only structural findings that have NOT been
// proven via Anvil or Medusa. They are surfaced separately from Findings so
// the proof-gated scanner does not report unproven leads as vulnerabilities.
type LeadReport struct {
	RuleID          string `json:"rule_id"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	ContractAddress string `json:"contract_address"`
	ContractRole    string `json:"contract_role"`
	Evidence        string `json:"evidence"`
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
	LeadsCount       int    `json:"leads_count"`
}

type SkippedProtocol struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Reason string `json:"reason"`
}

type Report struct {
	Metadata RunMetadata       `json:"metadata"`
	Findings []FindingReport   `json:"findings"`
	Leads    []LeadReport      `json:"leads"`
	Skipped  []SkippedProtocol `json:"skipped"`
}

func BuildReport(
	meta RunMetadata,
	findings []FindingReport,
	leads []LeadReport,
	skipped []SkippedProtocol,
) *Report {
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].TVLUSD > findings[j].TVLUSD
	})
	for i := range findings {
		findings[i].Rank = i + 1
	}

	// Sort leads by severity then by category for stable output
	severityRank := func(s string) int {
		switch s {
		case "critical":
			return 0
		case "high":
			return 1
		case "medium":
			return 2
		case "low":
			return 3
		default:
			return 4
		}
	}
	sort.SliceStable(leads, func(i, j int) bool {
		return severityRank(leads[i].Severity) < severityRank(leads[j].Severity)
	})

	meta.SchemaVersion = "11.0"
	meta.Timestamp = time.Now().UTC().Format(time.RFC3339)
	meta.VulnerableCount = len(findings)
	meta.LeadsCount = len(leads)
	meta.ProtocolsSkipped = len(skipped)

	return &Report{
		Metadata: meta,
		Findings: findings,
		Leads:    leads,
		Skipped:  skipped,
	}
}

func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "=== BASE PROTOCOL SPOT-AMM EXPOSURE SCAN (v11.0) ===\n")
	fmt.Fprintf(w, "Category: %s   Block: %d   %s\n",
		r.Metadata.CategoryKeyword, r.Metadata.BlockNumber, r.Metadata.Timestamp)
	fmt.Fprintf(w, "Protocols found: %d   scanned: %d   skipped: %d\n",
		r.Metadata.ProtocolsFound, r.Metadata.ProtocolsScanned, r.Metadata.ProtocolsSkipped)
	fmt.Fprintf(w, "Total flags: %d   proven vulnerable: %d   leads: %d\n\n",
		r.Metadata.TotalFlags, r.Metadata.VulnerableCount, r.Metadata.LeadsCount)

	// ---- FINDINGS: only proven vulnerabilities ----
	fmt.Fprintf(w, "--- FINDINGS (proven via Anvil / Medusa) (%d) ---\n", len(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "(no proven vulnerabilities)")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%d] %s  [%s]  tvl=$%.0f\n", f.Rank, f.Protocol, f.Category, f.TVLUSD)
		for _, fl := range f.Flags {
			fmt.Fprintf(w, "     - %s [%s] @ %s (%s)\n",
				fl.RuleID, fl.Severity, fl.ContractAddress, fl.ContractRole)

			if fl.LLMVerdict != "" {
				fmt.Fprintf(w, "       LLM: %s\n", fl.LLMVerdict)
			}

			if len(fl.Suppressors) > 0 {
				fmt.Fprintf(w, "       Suppressors: %v\n", fl.Suppressors)
			}
		}
	}

	// ---- LEADS: bytecode-only, unproven ----
	if len(r.Leads) > 0 {
		fmt.Fprintf(w, "\n--- LEADS (bytecode-only, unproven) (%d) ---\n", len(r.Leads))
		for _, l := range r.Leads {
			fmt.Fprintf(w, "  %-28s [%s] @ %s (%s)\n",
				l.RuleID, l.Severity, l.ContractAddress, l.ContractRole)
			if l.Evidence != "" {
				fmt.Fprintf(w, "     evidence: %s\n", l.Evidence)
			}
		}
	}

	// ---- SKIPPED ----
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
