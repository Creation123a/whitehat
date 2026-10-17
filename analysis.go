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
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================
// Etherscan Response Types
// =============================================================

type etherscanSourceResult struct {
	SourceCode     string `json:"SourceCode"`
	ABI            string `json:"ABI"`
	ContractName   string `json:"ContractName"`
	Proxy          string `json:"Proxy"`
	Implementation string `json:"Implementation"`
}

type etherscanResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// =============================================================
// Proxy & Source Resolution
// =============================================================

func ResolveImplementation(ctx context.Context, client *ethclient.Client, addr common.Address) common.Address {
	slot := common.HexToHash(EIP1967ImplementationSlot)
	raw, err := client.StorageAt(ctx, addr, slot, nil)
	if err != nil || len(raw) == 0 {
		return common.Address{}
	}
	impl := common.BytesToAddress(raw)
	if impl != (common.Address{}) {
		code, err := client.CodeAt(ctx, impl, nil)
		if err == nil && len(code) > 0 {
			return impl
		}
	}
	return common.Address{}
}

func UnwrapSource(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "{") && !strings.HasPrefix(raw, "{{") {
		return extractSourcesFromJSON(raw)
	}
	if strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		inner := raw[1 : len(raw)-1]
		return extractSourcesFromJSON(inner)
	}
	return raw
}

func extractSourcesFromJSON(jsonStr string) string {
	var parsed struct {
		Sources map[string]struct {
			Content string `json:"content"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, src := range parsed.Sources {
		sb.WriteString(src.Content)
		sb.WriteString("\n")
	}
	return sb.String()
}

// FetchVerifiedSource calls Etherscan V2 getsourcecode for the
// given address on Base. It handles both the success case (an
// array) and the error case (a string) in the `result` field.
func FetchVerifiedSource(ctx context.Context, addr common.Address) (string, string, error) {
	q := url.Values{}
	q.Set("chainid", fmt.Sprintf("%d", EtherscanChainID))
	q.Set("module", "contract")
	q.Set("action", "getsourcecode")
	q.Set("address", addr.Hex())
	q.Set("apikey", EtherscanAPIKey)

	full := EtherscanBaseURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return "", "", err
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed etherscanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", fmt.Errorf("etherscan decode: %w", err)
	}

	// Etherscan returns Status "0" and a string in Result when it fails.
	if parsed.Status == "0" {
		return "", "", fmt.Errorf("etherscan: %s", string(parsed.Result))
	}

	var results []etherscanSourceResult
	if err := json.Unmarshal(parsed.Result, &results); err != nil {
		return "", "", fmt.Errorf("etherscan result decode: %w", err)
	}
	if len(results) == 0 {
		return "", "", fmt.Errorf("etherscan: no result for %s", addr.Hex())
	}
	
	src := results[0].SourceCode
	if src == "" || strings.Contains(src, "not verified") {
		return "", "", fmt.Errorf("etherscan: source not verified for %s", addr.Hex())
	}
	// Add this right before return UnwrapSource(src)...
time.Sleep(350 * time.Millisecond) 

	return UnwrapSource(src), results[0].ContractName, nil
}

// =============================================================
// Dependency Extraction
// =============================================================

var addressRegex = regexp.MustCompile(`0x[a-fA-F0-9]{40}`)

// ExtractDependencies scans source code for addresses and checks
// if they have bytecode on the fork to filter out fake addresses,
// masks, and hex constants.
func ExtractDependencies(ctx context.Context, client *ethclient.Client, source string, self common.Address) []common.Address {
	matches := addressRegex.FindAllString(source, -1)
	seen := make(map[common.Address]bool)
	var out []common.Address
	for _, m := range matches {
		a := common.HexToAddress(m)
		if a == (common.Address{}) || a == self {
			continue
		}
		
		lower := strings.ToLower(m)
		// Skip obvious masks and placeholders
		if strings.HasPrefix(lower, "0x000") || strings.HasPrefix(lower, "0xfff") || 
		   strings.HasPrefix(lower, "0xaaa") || strings.HasPrefix(lower, "0x777") {
			continue
		}
		if lower == "0x360894a13ba1a3210667c828492db98dca3e2076" { // Sliced EIP1967 slot
			continue
		}

		// Check if it actually has code on-chain
		code, err := client.CodeAt(ctx, a, nil)
		if err != nil || len(code) == 0 {
			continue
		}

		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// =============================================================
// Regex Rules & Scanning
// =============================================================

type regexRule struct {
	ID       string
	Category string
	Severity string
	Pattern  *regexp.Regexp
}

var regexRules = []regexRule{
	{ID: "A1", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`getReserves\s*\(`)},
	{ID: "A2", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`slot0\s*\(\)`)},
	{ID: "A3", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`sqrtPriceX96`)},
	{ID: "A4", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`latestAnswer\s*\(`)},
	{ID: "A5", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`get_virtual_price\s*\(`)},
	{ID: "A6", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`get_dy\s*\(`)},
	{ID: "A7", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)`)},
	
	// Fixed C1 to ignore ** (exponentiation)
	{ID: "C1", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`[/]\s*[\w()]+\s*\*\s*[^*/]`)},
	{ID: "C2", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`\w+\s*/\s*\w+\s*\*\s*\w+`)},
	{ID: "C3", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`div\s*\([^)]*\)\s*\.mul\s*\(`)},
	
	{ID: "D1", Category: "stale-oracle", Severity: "medium", Pattern: regexp.MustCompile(`latestRoundData\s*\(`)},
	{ID: "D2", Category: "stale-oracle", Severity: "medium", Pattern: regexp.MustCompile(`latestAnswer\s*\(`)},
	
	{ID: "E1", Category: "decimal-mismatch", Severity: "medium", Pattern: regexp.MustCompile(`/\s*1e8`)},
	{ID: "E2", Category: "decimal-mismatch", Severity: "medium", Pattern: regexp.MustCompile(`uint256\(price\)\s*\*\s*1e10`)},
	
	{ID: "F1", Category: "reentrancy", Severity: "critical", Pattern: regexp.MustCompile(`get_virtual_price\s*\(`)},
	{ID: "F2", Category: "reentrancy", Severity: "critical", Pattern: regexp.MustCompile(`getReserves\s*\(`)},
	
	{ID: "I1", Category: "lp-valuation", Severity: "high", Pattern: regexp.MustCompile(`getReserves\s*\(\)[\s\S]{0,200}totalSupply\s*\(\)`)},
}

func RunRegexScan(source string) []FlagReport {
	var flags []FlagReport
	lines := strings.Split(source, "\n")

	for _, rule := range regexRules {
		locs := rule.Pattern.FindAllStringIndex(source, -1)
		for _, loc := range locs {
			lineStart := strings.Count(source[:loc[0]], "\n")
			lineEnd := strings.Count(source[:loc[1]], "\n")

			ctxStart := lineStart - 10
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := lineEnd + 10
			if ctxEnd >= len(lines) {
				ctxEnd = len(lines) - 1
			}
			snippet := strings.Join(lines[ctxStart:ctxEnd+1], "\n")

			flag := FlagReport{
				RuleID:    rule.ID,
				Category:  rule.Category,
				Severity:  rule.Severity,
				Snippet:   snippet,
				LineStart: lineStart + 1,
				LineEnd:   lineEnd + 1,
			}
			flag.Suppressors = checkSuppressors(rule.ID, snippet)
			flags = append(flags, flag)
		}
	}
	return flags
}

func checkSuppressors(ruleID, snippet string) []string {
	var out []string
	lower := strings.ToLower(snippet)

	if regexp.MustCompile(`observe\s*\(|consult\s*\(|twap|timeweighted`).MatchString(lower) {
		out = append(out, "has_twap_guard")
	}
	if regexp.MustCompile(`nonreentrant`).MatchString(lower) {
		out = append(out, "has_reentrancy_guard")
	}
	if regexp.MustCompile(`updatedat|heartbeat|maxdelay|answeredinround`).MatchString(lower) {
		out = append(out, "has_freshness_check")
	}
	if regexp.MustCompile(`decimals\s*\(|10\s*\*\*\s*decimals`).MatchString(lower) {
		out = append(out, "has_decimals_check")
	}
	return out
}
