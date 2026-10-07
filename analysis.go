package main

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ---------- Candidate ----------

// Candidate is produced by discovery.go and consumed here.
// Protocol and Pool carry the provenance needed to populate Finding.
type Candidate struct {
	Address  common.Address
	Protocol string         // "morpho" | "aave"
	Pool     common.Address // lending pool the candidate was discovered from
}

// ---------- Detection selectors ----------

// selectors recognized during the bytecode scan.
var detectorSelectors = map[[4]byte]string{
	{0x09, 0x02, 0xf1, 0xac}: "getReserves()",    // Uniswap V2
	{0x38, 0x50, 0xc7, 0xbd}: "slot0()",          // Uniswap V3
	{0xfe, 0xaf, 0x96, 0x8c}: "latestRoundData()", // Chainlink
	{0x88, 0x3b, 0xdb, 0xfd}: "observe()",        // Uniswap V3 TWAP
}

const analysisWorkers = 16

// ---------- Entry point ----------

// AnalyzeCandidates scans each candidate's runtime bytecode, applies the
// SPOT_DEPENDENT classification rule, and returns only the findings that
// pass. Non-SPOT_DEPENDENT candidates are silently dropped.
func AnalyzeCandidates(
	ctx context.Context,
	client *ethclient.Client,
	candidates []Candidate,
) []Finding {

	in := make(chan Candidate)
	out := make(chan Finding)

	var wg sync.WaitGroup
	for i := 0; i < analysisWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range in {
				if f, ok := analyzeOne(ctx, client, c); ok {
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, c := range candidates {
			select {
			case in <- c:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var findings []Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings
}

// ---------- Per-candidate analysis ----------

func analyzeOne(
	ctx context.Context,
	client *ethclient.Client,
	c Candidate,
) (Finding, bool) {

	code, err := client.CodeAt(ctx, c.Address, nil)
	if err != nil || len(code) == 0 {
		return Finding{}, false
	}

	hits := scanSelectors(code)

	// One-level call-graph expansion: EIP-1967 proxy implementation.
	if impl, ok := readEIP1967Impl(ctx, client, c.Address); ok &&
		impl != (common.Address{}) {
		if implCode, err := client.CodeAt(ctx, impl, nil); err == nil && len(implCode) > 0 {
			for name := range scanSelectors(implCode) {
				hits[name] = true
			}
		}
	}

	// Classification rule:
	//   contains getReserves() OR slot0()
	//   AND does NOT contain latestRoundData() OR observe()
	if !hits["getReserves()"] && !hits["slot0()"] {
		return Finding{}, false
	}
	if hits["latestRoundData()"] || hits["observe()"] {
		return Finding{}, false
	}

	// Deterministic selector order for the report.
	var sels []string
	if hits["getReserves()"] {
		sels = append(sels, "getReserves()")
	}
	if hits["slot0()"] {
		sels = append(sels, "slot0()")
	}

	return Finding{
		Vault:     c.Address,
		Protocol:  c.Protocol,
		Pool:      c.Pool,
		Selectors: sels,
		// Verified and Evidence left zero — set by simulation.go.
	}, true
}

// ---------- Bytecode scan ----------

// scanSelectors linearly scans runtime bytecode for PUSH4 <selector>.
// It does not disassemble; it does not distinguish code from data.
// This is intentional and matches the spec's classification rule.
func scanSelectors(code []byte) map[string]bool {
	found := make(map[string]bool)
	for i := 0; i+5 <= len(code); i++ {
		if code[i] != 0x63 { // PUSH4
			continue
		}
		var sel [4]byte
		copy(sel[:], code[i+1:i+5])
		if name, ok := detectorSelectors[sel]; ok {
			found[name] = true
		}
	}
	return found
}
