package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	OllamaAPIBase = "http://localhost:11434/api/chat"
	OllamaModel   = "qwen2.5-coder:3b"
)

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  ollamaOptions   `json:"options"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}

type ollamaResponse struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	Done bool `json:"done"`
}

// Domain-specific focus areas injected into the LLM prompt
var domainFocus = map[string]string{
	"pricing": "Focus on division before multiplication, precision loss, and rounding directions. Look for (A / B) * C patterns or raw multiplications (A * B) used in fee/reward calculations.",
	"oracle":  "Focus on stale prices, missing heartbeat checks, and spot AMM manipulation. Look for Unresolved_3850c7bd (slot0) or Unresolved_feaf968c (latestRoundData) used without TWAP checks.",
	"lending": "Focus on liquidation math, collateral valuation, and bad debt handling. Look for manipulable collateral math, missing bounds in liquidations, or unchecked arithmetic.",
	"staking": "Focus on reward accounting, share inflation, and reentrancy. Look for 1-wei deposit attacks (ERC-4626), unchecked external calls modifying rewards, or precision loss in share calculations.",
	"general": "Focus on any critical math vulnerabilities, precision loss, unchecked external calls, or access control bypasses.",
}

// The core prompt template. It is structured to force the LLM to find the root cause of a PROVEN exploit.
const systemPromptTemplate = `You are an expert smart contract security auditor.
Contract Role: %s
Contract Name: %s

### PROOF OF EXPLOIT ###
%s

### CRITICAL INSTRUCTION 1 (DECOMPILED CODE CONTEXT) ###
This code is decompiled pseudo-Solidity. 
- Variables are generic (var_0, storage_0).
- Function calls are Unresolved_xxxxx.
- Constants are hex (e.g., 0x0de0b6b3a7640000 = 1e18).
- DO NOT flag reentrancy for staticcall or Unresolved_ calls. They cannot modify state.
- DO NOT flag basic require statements.
- Standard library logic (Solady, OpenZeppelin) is SAFE.

### CRITICAL INSTRUCTION 2 (DOMAIN FOCUS - %s) ###
%s

### ROOT CAUSE ANALYSIS ###
A vulnerability has been PROVEN by the Anvil proof above. Do not guess if it is vulnerable. You must explain the exact arithmetic flaw in the decompiled code that causes the proven behavior. Trace the variables to show how the manipulated price or value flows into a critical calculation (like collateral value, health factor, or share issuance).

Respond in EXACTLY this format:
VERDICT: VULNERABLE
TYPE: <vulnerability type>
LOCATION: <line number or code fragment>
REASON: <one sentence explaining the precise arithmetic flaw that caused the Anvil proof>

Analyze: `

// Static-only prompt (when no Anvil proof exists)
const staticPromptTemplate = `You are an expert smart contract security auditor.
Contract Role: %s
Contract Name: %s

CRITICAL INSTRUCTION 1 (DECOMPILED CODE CONTEXT):
This code is decompiled pseudo-Solidity. 
- Variables are generic (var_0, storage_0).
- Function calls are Unresolved_xxxxx.
- Constants are hex (e.g., 0x0de0b6b3a7640000 = 1e18).
- DO NOT flag reentrancy for staticcall or Unresolved_ calls. They cannot modify state.
- DO NOT flag basic require statements.
- Standard library logic (Solady, OpenZeppelin) is SAFE.

CRITICAL INSTRUCTION 2 (DOMAIN FOCUS - %s):
%s

Respond in EXACTLY this format:
VERDICT: <VULNERABLE|SAFE>
TYPE: <vulnerability type>
LOCATION: <line number or code fragment>
REASON: <one sentence>

Analyze: `

// AskLocalLLM sends a snippet to the local Ollama instance.
func AskLocalLLM(ctx context.Context, snippet, contractName, contractRole string, domain string, anvilProof string) (string, error) {
	// Truncate to prevent context overflow
	if len(snippet) > 8000 {
		snippet = snippet[:8000] + "\n... [TRUNCATED FOR LLM CONTEXT LIMIT] ..."
	}

	focus, exists := domainFocus[domain]
	if !exists {
		focus = domainFocus["general"]
	}

	var sysPrompt string
	if anvilProof != "" {
		// We have proof of an exploit. Force the LLM to find the root cause.
		sysPrompt = fmt.Sprintf(systemPromptTemplate, contractRole, contractName, anvilProof, strings.ToUpper(domain), focus)
	} else {
		// No proof. Fallback to static analysis.
		sysPrompt = fmt.Sprintf(staticPromptTemplate, contractRole, contractName, strings.ToUpper(domain), focus)
	}

	reqBody := ollamaRequest{
		Model: OllamaModel,
		Messages: []ollamaMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)},
		},
		Stream: false,
		Options: ollamaOptions{
			Temperature: 0.1,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OllamaAPIBase, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	c := &http.Client{Timeout: 300 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama connection failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed ollamaResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}

	rawText := strings.TrimSpace(parsed.Message.Content)
	log.Printf("scanner[llm]: RAW LLM OUTPUT [%s]: %s", domain, strings.ReplaceAll(rawText, "\n", " "))

	return rawText, nil
}

// ParseVerdict extracts VULNERABLE / SAFE from the LLM response with strict matching.
func ParseVerdict(response string) string {
	upper := strings.ToUpper(response)

	// Strict check to avoid matching "Vulnerability" in the TYPE field
	if strings.Contains(upper, "VERDICT: VULNERABLE") {
		return "VULNERABLE"
	}
	if strings.Contains(upper, "VERDICT: SAFE") {
		return "SAFE"
	}
	return "UNKNOWN"
}
