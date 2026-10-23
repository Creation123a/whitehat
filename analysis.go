package main

import (
	"context"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================
// RPC & Bytecode Resolution
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

func FetchBytecode(ctx context.Context, client *ethclient.Client, addr common.Address) ([]byte, error) {
	code, err := client.CodeAt(ctx, addr, nil)
	if err != nil {
		return nil, err
	}
	return code, nil
}

// =============================================================
// Dependency Extraction & Regex
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
		if lower == "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" {
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

type regexRule struct {
	ID       string
	Category string
	Severity string
	Pattern  *regexp.Regexp
}


var regexRules = []regexRule{
	// --- 1. Decompiled Spot Price Reads (Critical) ---
	{ID: "A1", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`Unresolved_0902f1ac`)}, // getReserves()
	{ID: "A2", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`Unresolved_3850c7bd`)}, // slot0()
	{ID: "A4", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`Unresolved_feaf968c`)}, // latestRoundData()
	{ID: "A5", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`Unresolved_50d25bcd`)}, // latestAnswer()
	{ID: "A6", Category: "spot-amm", Severity: "critical", Pattern: regexp.MustCompile(`Unresolved_bb7b8b80`)}, // get_virtual_price()

	// --- 2. Precision Loss / Division Before Multiplication (High) ---
	// Matches: (var_a / var_b) * var_c  OR  (storage_0 / var_a) * 0x0de0b6b3a7640000
	// This is the classic precision loss pattern. In decompiled code, division truncates, 
	// so multiplying afterwards loses value[reference:1].
	{ID: "C1", Category: "precision", Severity: "high", Pattern: regexp.MustCompile(`\(\s*[\w\[\]\.]+\s*/\s*[\w\[\]\.]+\s*\)\s*\*`)},
	
	// Matches: var_a / var_b * var_c (left-to-right evaluation)
	{ID: "C2", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`[\w\[\]\.]+\s*/\s*[\w\[\]\.]+\s*\*\s*[\w\[\]\.]+`)},

	// --- 3. Arithmetic Overflow / SafeMath Bypass (High) ---
	// In decompiled code, SafeMath is usually resolved as Unresolved_..., but raw math 
	// appears as standard operators. A raw multiplication of two variables is a huge red flag.
	// Matches: var_a * var_b  OR  storage_0 * var_a
	{ID: "O1", Category: "overflow", Severity: "high", Pattern: regexp.MustCompile(`(var_\w+|storage_\w+)\s*\*\s*(var_\w+|storage_\w+)`)},

	// Matches: var_a + var_b (raw addition, potential overflow if not checked)[reference:2]
	{ID: "O2", Category: "overflow", Severity: "medium", Pattern: regexp.MustCompile(`(var_\w+|storage_\w+)\s*\+\s*(var_\w+|storage_\w+)`)},

	// --- 4. Rounding Errors (Medium) ---
	// Matches multiplication by 1e18 followed by division. This usually *loses* precision 
	// if the order is wrong, or implies a missing scale factor.
	// 0x0de0b6b3a7640000 is 1e18.
	{ID: "R1", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`0x0de0b6b3a7640000\s*/\s*[\w\[\]\.]+`)},
	{ID: "R2", Category: "precision", Severity: "medium", Pattern: regexp.MustCompile(`/\s*0x0de0b6b3a7640000\s*\*`)},
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
