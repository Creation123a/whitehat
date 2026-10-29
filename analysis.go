package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
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
// Dependency Extraction
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

// =============================================================
// Chunking & Classification
// =============================================================

var functionBoundaryRegex = regexp.MustCompile(`function\s+Unresolved_[a-zA-Z0-9]+`)

// ChunkByFunction splits the decompiled source into individual function chunks
// based on the `function Unresolved_...` boundaries that Heimdall outputs.
func ChunkByFunction(source string) []string {
	indices := functionBoundaryRegex.FindAllStringIndex(source, -1)
	if len(indices) == 0 {
		return []string{source}
	}

	var chunks []string
	for i := 0; i < len(indices); i++ {
		start := indices[i][0]
		end := len(source)
		if i < len(indices)-1 {
			end = indices[i+1][0]
		}
		chunks = append(chunks, source[start:end])
	}
	return chunks
}

// ClassifyChunk determines the primary domain of a function chunk
// by counting keyword occurrences.
func ClassifyChunk(chunk string) string {
	lower := strings.ToLower(chunk)
	
	counts := map[string]int{
		"pricing": 0,
		"oracle":  0,
		"lending": 0,
		"staking": 0,
	}

	for _, kw := range []string{"mul", "div", "add", "sub", "0x0de0b6b3a7640000"} {
		counts["pricing"] += strings.Count(lower, kw)
	}
	for _, kw := range []string{"oracle", "latestrounddata", "latestanswer", "slot0", "getreserves"} {
		counts["oracle"] += strings.Count(lower, kw)
	}
	for _, kw := range []string{"borrow", "repay", "liquidate", "collateral", "debt", "supply"} {
		counts["lending"] += strings.Count(lower, kw)
	}
	for _, kw := range []string{"stake", "unstake", "reward", "earned"} {
		counts["staking"] += strings.Count(lower, kw)
	}

	maxDomain := "general"
	maxCount := 0
	for domain, count := range counts {
		if count > maxCount {
			maxCount = count
			maxDomain = domain
		}
	}
	
	return maxDomain
}

// =============================================================
// Bytecode-Level Rules (v11.0 Pre-Decompilation)
// =============================================================

type bytecodeRule struct {
	ID          string
	Category    string
	Severity    string
	MustHave    []string // all required selectors (hex without 0x)
	MustNotHave []string // any of these disqualifies
}

var bytecodeRules = []bytecodeRule{
	{ID: "BC_ORACLE_SPOT", Category: "mixed-source", Severity: "critical",
		MustHave: []string{"feaf968c", "0902f1ac"}, // Chainlink latestRoundData + Uniswap V2 getReserves
	},
	{ID: "BC_ORACLE_SPOT_V3", Category: "mixed-source", Severity: "critical",
		MustHave: []string{"feaf968c", "3850c7bd"}, // Chainlink latestRoundData + Uniswap V3 slot0
	},
	{ID: "BC_VAULT_NO_VIRTUAL", Category: "vault", Severity: "high",
		MustHave: []string{"01e1d114", "18160ddd"}, // totalAssets + totalSupply
		MustNotHave: []string{"07a2d13a"},          // convertToAssets (proxy for virtual offset)
	},
	{ID: "BC_LENDING_UNCHECKED", Category: "lending", Severity: "high",
		MustHave: []string{"c5ebeaec"},             // borrow(uint256)
		MustNotHave: []string{"5ec88c79"},          // getAccountLiquidity (missing health check)
	},
}

// ExtractSelectorsFromBytecode scans raw EVM bytecode for PUSH4 (0x63) and returns a set.
func ExtractSelectorsFromBytecode(code []byte) map[uint32]bool {
	out := make(map[uint32]bool)
	for i := 0; i+5 <= len(code); i++ {
		if code[i] == 0x63 { // PUSH4 opcode
			val := uint32(code[i+1])<<24 | uint32(code[i+2])<<16 | uint32(code[i+3])<<8 | uint32(code[i+4])
			out[val] = true
		}
	}
	return out
}

// RunBytecodeRules checks the extracted selector map against the structural rules.
// This runs before any decompilation.
func RunBytecodeRules(selectors map[uint32]bool) []FlagReport {
	var flags []FlagReport
	for _, rule := range bytecodeRules {
		match := true
		
		// Check MustHave
		for _, hexStr := range rule.MustHave {
			if len(hexStr) != 8 { 
				match = false
				break 
			}
			val, err := strconv.ParseUint(hexStr, 16, 32)
			if err != nil || !selectors[uint32(val)] {
				match = false
				break
			}
		}
		if !match { continue }

		// Check MustNotHave
		for _, hexStr := range rule.MustNotHave {
			if len(hexStr) != 8 { continue }
			val, err := strconv.ParseUint(hexStr, 16, 32)
			if err == nil && selectors[uint32(val)] {
				match = false
				break
			}
		}

		if match {
			flags = append(flags, FlagReport{
				RuleID:     rule.ID,
				Category:   rule.Category,
				Severity:   rule.Severity,
				Snippet:    "Bytecode contains suspicious selector combination.",
				LLMVerdict: "UNPROVEN_LEAD",
			})
		}
	}
	return flags
}

// =============================================================
// Professional Regex Rules (v11.0 Post-Decompilation)
// =============================================================

type regexRule struct {
	ID       string
	Category string
	Severity string
	Pattern  *regexp.Regexp
}

var regexRules = []regexRule{
	// 1. Oracle without staleness check
	{ID: "ORACLE_STALE", Category: "oracle", Severity: "critical",
		Pattern: regexp.MustCompile(`latestRoundData\s*\(\s*\)(?![\s\S]{0,200}(updatedAt|heartbeat|maxDelay))`)},

	// 2. Spot AMM read without TWAP
	{ID: "SPOT_NO_TWAP", Category: "spot-amm", Severity: "critical",
		Pattern: regexp.MustCompile(`(getReserves\s*\(\s*\)|slot0\s*\(\s*\)|sqrtPriceX96)(?![\s\S]{0,300}(observe|consult|TWAP|twap|timeWeighted))`)},

	// 3. Division before multiplication
	{ID: "DIV_BEFORE_MUL", Category: "precision", Severity: "high",
		Pattern: regexp.MustCompile(`\([^)]*\s*/\s*[^)]*\)\s*\*`)},

	// 4. ERC-4626 inflation without virtual shares
	{ID: "ERC4626_INFLATE", Category: "vault", Severity: "high",
		Pattern: regexp.MustCompile(`totalSupply\s*\(\s*\)\s*==\s*0(?![^}]{0,200}(virtual|dead|_decimalsOffset|1e[0-9]+))`)},

	// 5. Answered-in-round missing
	{ID: "CHAINLINK_ROUND", Category: "oracle", Severity: "medium",
		Pattern: regexp.MustCompile(`latestRoundData\s*\(\s*\)(?![\s\S]{0,300}answeredInRound\s*>=?\s*roundId)`)},

	// 6. Self-balance accounting (donation attack surface)
	{ID: "SELF_BALANCE", Category: "vault", Severity: "high",
		Pattern: regexp.MustCompile(`balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)`)},

	// 7. Liquidation without health bound
	{ID: "LIQ_NO_HEALTH", Category: "lending", Severity: "critical",
		Pattern: regexp.MustCompile(`function\s+liquidate\s*\([^)]*\)[^{]*\{(?:(?!healthFactor|getAccountLiquidity|shortfall)[\s\S]){0,500}`)},
}

func RunRegexScan(source string) []FlagReport {
	var flags []FlagReport
	lines := strings.Split(source, "\n")
	
	for _, rule := range regexRules {
		locs := rule.Pattern.FindAllStringIndex(source, -1)
		for _, loc := range locs {
			lineStart := strings.Count(source[:loc[0]], "\n")
			lineEnd := strings.Count(source[:loc[1]], "\n")

			ctxStart := lineStart - 5
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := lineEnd + 5
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
