package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================
// Phase 3: Fetch verified source + regex scan
// =============================================================

type RegexFlag struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Snippet     string   `json:"snippet"`
	LineStart   int      `json:"line_start"`
	LineEnd     int      `json:"line_end"`
	Suppressors []string `json:"suppressors,omitempty"`
}

// etherscanResponse is the Etherscan V2 getsourcecode response.
type etherscanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  []struct {
		SourceCode string `json:"SourceCode"`
		ABI        string `json:"ABI"`
		ContractName string `json:"ContractName"`
	} `json:"result"`
}

// FetchVerifiedSource calls Etherscan V2 getsourcecode for the
// given address on Base.
func FetchVerifiedSource(ctx context.Context, addr common.Address) (string, error) {
	q := url.Values{}
	q.Set("chainid", fmt.Sprintf("%d", EtherscanChainID))
	q.Set("module", "contract")
	q.Set("action", "getsourcecode")
	q.Set("address", addr.Hex())
	q.Set("apikey", EtherscanAPIKey)

	full := EtherscanBaseURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return "", err
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed etherscanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("etherscan decode: %w", err)
	}
	if len(parsed.Result) == 0 {
		return "", fmt.Errorf("etherscan: no result for %s", addr.Hex())
	}
	src := parsed.Result[0].SourceCode
	if src == "" || strings.Contains(src, "not verified") {
		return "", fmt.Errorf("etherscan: source not verified for %s", addr.Hex())
	}
	return src, nil
}

// =============================================================
// Regex rules
// =============================================================

type regexRule struct {
	ID       string
	Category string
	Severity string
	Pattern  *regexp.Regexp
}

var regexRules = []regexRule{
	// Category A — Spot AMM price reads
	{ID: "A1", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`getReserves\s*\(`)},
	{ID: "A2", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`slot0\s*\(\)`)},
	{ID: "A3", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`sqrtPriceX96`)},
	{ID: "A4", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`latestAnswer\s*\(`)},
	{ID: "A5", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`get_virtual_price\s*\(`)},
	{ID: "A6", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`get_dy\s*\(`)},
	{ID: "A7", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)`)},

	// Category C — Precision / division-before-multiplication
	{ID: "C1", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`[/]\s*\w+\s*\*`)},
	{ID: "C2", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`\w+\s*/\s*\w+\s*\*\s*\w+`)},
	{ID: "C3", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`div\s*\([^)]*\)\s*\.mul\s*\(`)},

	// Category D — Stale oracle
	{ID: "D1", Category: "stale-oracle", Severity: "medium", Pattern: regexp.MustCompile(`latestRoundData\s*\(`)},
	{ID: "D2", Category: "stale-oracle", Severity: "medium", Pattern: regexp.MustCompile(`latestAnswer\s*\(`)},

	// Category E — Oracle decimal mismatch
	{ID: "E1", Category: "decimal-mismatch", Severity: "medium", Pattern: regexp.MustCompile(`/\s*1e8`)},
	{ID: "E2", Category: "decimal-mismatch", Severity: "medium", Pattern: regexp.MustCompile(`uint256\(price\)\s*\*\s*1e10`)},

	// Category F — Read-only reentrancy
	{ID: "F1", Category: "reentrancy", Severity: "critical", Pattern: regexp.MustCompile(`get_virtual_price\s*\(`)},
	{ID: "F2", Category: "reentrancy", Severity: "critical", Pattern: regexp.MustCompile(`getReserves\s*\(`)},

	// Category I — LP token valuation
	{ID: "I1", Category: "lp-valuation", Severity: "high", Pattern: regexp.MustCompile(`getReserves\s*\(\)[\s\S]{0,200}totalSupply\s*\(\)`)},
}

// RunRegexScan applies every rule to the source. Returns flags
// grouped by rule, with snippets and suppressor annotations.
func RunRegexScan(source string) []RegexFlag {
	var flags []RegexFlag
	lines := strings.Split(source, "\n")

	for _, rule := range regexRules {
		locs := rule.Pattern.FindAllStringIndex(source, -1)
		for _, loc := range locs {
			lineStart := strings.Count(source[:loc[0]], "\n")
			lineEnd := strings.Count(source[:loc[1]], "\n")

			// Extract ±10 lines of context.
			ctxStart := lineStart - 10
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := lineEnd + 10
			if ctxEnd >= len(lines) {
				ctxEnd = len(lines) - 1
			}
			snippet := strings.Join(lines[ctxStart:ctxEnd+1], "\n")

			flag := RegexFlag{
				RuleID:    rule.ID,
				Category:  rule.Category,
				Severity:  rule.Severity,
				Snippet:   snippet,
				LineStart: lineStart + 1,
				LineEnd:   lineEnd + 1,
			}

			// Suppression markers.
			flag.Suppressors = checkSuppressors(rule.ID, snippet)

			flags = append(flags, flag)
		}
	}
	return flags
}

// checkSuppressors returns suppression markers found in the snippet.
func checkSuppressors(ruleID, snippet string) []string {
	var out []string
	lower := strings.ToLower(snippet)

	twapGuard := regexp.MustCompile(`observe\s*\(|consult\s*\(|twap|timeweighted`)
	reentrancyGuard := regexp.MustCompile(`nonreentrant`)
	freshnessCheck := regexp.MustCompile(`updatedat|heartbeat|maxdelay|answeredinround`)
	decimalsCheck := regexp.MustCompile(`decimals\s*\(|10\s*\*\*\s*decimals`)
	accessRestrict := regexp.MustCompile(`onlyowner|onlyrole|internal\s+view`)

	if twapGuard.MatchString(lower) {
		out = append(out, "has_twap_guard")
	}
	if reentrancyGuard.MatchString(lower) {
		out = append(out, "has_reentrancy_guard")
	}
	if freshnessCheck.MatchString(lower) {
		out = append(out, "has_freshness_check")
	}
	if decimalsCheck.MatchString(lower) {
		out = append(out, "has_decimals_check")
	}
	if accessRestrict.MatchString(lower) {
		out = append(out, "restricted_access")
	}
	return out
}
