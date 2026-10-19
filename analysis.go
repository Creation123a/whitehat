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
// Programmatic Proxy Linking (Etherscan V2)
// =============================================================

type BaseScanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

func LinkProxyToImplementation(ctx context.Context, proxyAddress, implAddress string) error {
	data := url.Values{}
	data.Set("address", proxyAddress)
	data.Set("expectedimplementation", implAddress)

	endpoint := fmt.Sprintf("%s?chainid=%d&module=contract&action=verifyproxycontract&apikey=%s", 
		EtherscanBaseURL, EtherscanChainID, EtherscanAPIKey)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to construct request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http transfer layer failure: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var baseResp BaseScanResponse
	if err := json.Unmarshal(bodyBytes, &baseResp); err != nil {
		return fmt.Errorf("invalid json footprint payload: %w", err)
	}

	if baseResp.Status != "1" {
		return fmt.Errorf("etherscan tracking initialization rejected: %s", baseResp.Result)
	}

	guidToken := baseResp.Result
	statusEndpoint := fmt.Sprintf("%s?chainid=%d&module=contract&action=checkproxyverification&guid=%s&apikey=%s", 
		EtherscanBaseURL, EtherscanChainID, guidToken, EtherscanAPIKey)
	
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	timeout := time.After(60 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout limit reached while verifying target guid: %s", guidToken)
		case <-ticker.C:
			statusResp, err := client.Get(statusEndpoint)
			if err != nil {
				continue 
			}
			statusBytes, _ := io.ReadAll(statusResp.Body)
			statusResp.Body.Close()

			var pollResp BaseScanResponse
			if err := json.Unmarshal(statusBytes, &pollResp); err != nil {
				continue
			}

			switch pollResp.Result {
			case "Pending", "Awaiting confirmation":
				// Keep polling
			case "Pass", "Proxy contract verification successful", "SUCCESS":
				return nil
			default:
				if pollResp.Status == "1" || strings.Contains(pollResp.Result, "Already Verified") {
					return nil
				}
				return fmt.Errorf("verification dropped with error: %s", pollResp.Result)
			}
		}
	}
}

// =============================================================
// Source Resolution & Proxy Checks
// =============================================================

func ResolveImplementation(ctx context.Context, client *ethclient.Client, addr common.Address) common.Address {
	// 1. EIP-1967 Slot
	slot := common.HexToHash(EIP1967ImplementationSlot)
	raw, _ := client.StorageAt(ctx, addr, slot, nil)
	if len(raw) > 0 {
		impl := common.BytesToAddress(raw)
		if impl != (common.Address{}) {
			return impl
		}
	}

	// 2. Legacy Transparent Proxy Slot
	legacySlot := common.HexToHash("0xa3f1a74d20ba3f5bb237cc54f6b8a73377b2212d7959d3317549ad8f949247df")
	rawLegacy, _ := client.StorageAt(ctx, addr, legacySlot, nil)
	if len(rawLegacy) > 0 {
		impl := common.BytesToAddress(rawLegacy)
		if impl != (common.Address{}) {
			return impl
		}
	}

	// 3. EIP-1167 Minimal Proxy
	code, err := client.CodeAt(ctx, addr, nil)
	if err == nil && len(code) >= 45 {
		hexCode := common.Bytes2Hex(code)
		if strings.HasPrefix(hexCode, "363d3d373d3d3d363d73") {
			impl := common.BytesToAddress(code[10:30])
			if impl != (common.Address{}) {
				return impl
			}
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

func fetchRawSource(ctx context.Context, addr common.Address) (string, string, error) {
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

	if parsed.Status == "0" {
		var errMsg string
		_ = json.Unmarshal(parsed.Result, &errMsg)
		return "", "", fmt.Errorf("%s", errMsg)
	}

	var results []etherscanSourceResult
	if err := json.Unmarshal(parsed.Result, &results); err != nil {
		return "", "", fmt.Errorf("etherscan result decode: %w", err)
	}
	if len(results) == 0 {
		return "", "", fmt.Errorf("etherscan: no result for %s", addr.Hex())
	}
	
	return results[0].SourceCode, results[0].ContractName, nil
}

func FetchVerifiedSource(ctx context.Context, client *ethclient.Client, addr common.Address) (string, string, error) {
	src, name, err := fetchRawSource(ctx, addr)
	
	if err != nil && strings.Contains(err.Error(), "not verified") {
		impl := ResolveImplementation(ctx, client, addr)
		if impl != (common.Address{}) {
			fmt.Printf("scanner[fix]: Attempting programmatic proxy linking for %s -> %s\n", addr.Hex(), impl.Hex())
			linkErr := LinkProxyToImplementation(ctx, addr.Hex(), impl.Hex())
			if linkErr == nil {
				time.Sleep(5 * time.Second)
				src, name, err = fetchRawSource(ctx, addr)
			}
		}
	}

	if err != nil {
		return "", "", err
	}
	if src == "" || strings.Contains(src, "not verified") {
		return "", "", fmt.Errorf("etherscan: source not verified for %s", addr.Hex())
	}

	// Rate limit sleep to respect Etherscan V2 (3 calls/sec)
	time.Sleep(400 * time.Millisecond)

	return UnwrapSource(src), name, nil
}

// =============================================================
// Dependency Extraction (AST string match)
// =============================================================

var addressRegex = regexp.MustCompile(`0x[a-fA-F0-9]{40}`)

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
		if strings.HasPrefix(lower, "0x000") || strings.HasPrefix(lower, "0xfff") || 
		   strings.HasPrefix(lower, "0xaaa") || strings.HasPrefix(lower, "0x777") {
			continue
		}
		if lower == "0x360894a13ba1a3210667c828492db98dca3e2076" {
			continue
		}

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
	
	// Fixed C1 to ignore ** (exponentiation) and common library math
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
			
			// Do not send known safe libraries to the LLM
			isSafeLib := false
			for _, s := range flag.Suppressors {
				if s == "known_safe_library" {
					isSafeLib = true
					break
				}
			}
			if isSafeLib {
				continue
			}

			flags = append(flags, flag)
		}
	}
	return flags
}

func checkSuppressors(ruleID, snippet string) []string {
	var out []string
	lower := strings.ToLower(snippet)

	knownLibs := []string{
		"credit to remco bloemen", "original credit to remco bloemen",
		"solady", "openzeppelin", "aave", 
		"the whitepaper contains reference", "expwad", "logwad", "muldiv", "sqr",
	}
	for _, lib := range knownLibs {
		if strings.Contains(lower, lib) {
			out = append(out, "known_safe_library")
			return out
		}
	}

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
