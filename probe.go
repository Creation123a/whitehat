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
	OllamaModel   = "qwen2.5-coder:3b" // Upgraded model
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

const systemPromptTemplate = `You are an expert smart contract security auditor.
Contract Role: %s
Contract Name: %s

CRITICAL INSTRUCTION 1 (DECOMPILED CODE CONTEXT):
This code is decompiled pseudo-Solidity. 
- Variables are generic (var_0, storage_0).
- Function calls are Unresolved_xxxxx.
- Constants are hex (e.g., 0x0de0b6b3a7640000 = 1e18).

CRITICAL INSTRUCTION 2 (MATH VULNERABILITIES):
You MUST carefully review the following flagged patterns:
1. "Division before multiplication" (e.g., (var_a / var_b) * var_c). This causes precision loss because Solidity truncates integer division. If this happens in a reward, fee, or share calculation, mark it VULNERABLE.
2. Raw arithmetic (var_a * var_b or var_a + var_b) without a SafeMath wrapper. If the inputs can be large, this can overflow. Mark it VULNERABLE if you see it in a token minting, transfer, or pricing function.
3. Standard AMM/Spot price reads (getReserves, slot0) used for pricing.

CRITICAL INSTRUCTION 3 (FALSE POSITIVE FILTER):
- DO NOT flag reentrancy for ` + "`staticcall`" + ` or ` + "`Unresolved_`" + ` calls.
- DO NOT flag basic require statements.
- Standard library logic (Solady, OpenZeppelin) is SAFE.

Respond in EXACTLY this format:
VERDICT: <VULNERABLE|SAFE>
TYPE: <vulnerability type>
LOCATION: <line number or code fragment>
REASON: <one sentence>

Analyze: `
// AskLocalLLM sends a snippet to the local Ollama instance.
func AskLocalLLM(ctx context.Context, snippet, contractName, contractRole string) (string, error) {
	// 3B model can handle a bit more context, but still needs truncation to prevent timeouts
	if len(snippet) > 8000 {
		snippet = snippet[:8000] + "\n... [TRUNCATED FOR LLM CONTEXT LIMIT] ..."
	}

	sysPrompt := fmt.Sprintf(systemPromptTemplate, contractRole, contractName)

	reqBody := ollamaRequest{
		Model: OllamaModel,
		Messages: []ollamaMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)},
		},
		Stream: false,
		Options: ollamaOptions{
			Temperature: 0.1, // Slight temp to avoid repetitive loops on 3B
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, OllamaAPIBase, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Increased timeout to 5 minutes for the 3B model
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

	// Print raw output for debugging
	rawText := strings.TrimSpace(parsed.Message.Content)
	log.Printf("scanner[llm]: RAW LLM OUTPUT: %s", strings.ReplaceAll(rawText, "\n", " "))

	return rawText, nil
}

// ParseVerdict extracts VULNERABLE / SAFE from the LLM response.
func ParseVerdict(response string) string {
	upper := strings.ToUpper(response)

	if strings.Contains(upper, "VULNERABLE") {
		return "VULNERABLE"
	}
	if strings.Contains(upper, "SAFE") {
		return "SAFE"
	}
	return "UNKNOWN"
}
