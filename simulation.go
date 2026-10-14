package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// =============================================================
// Phase 4: OpenRouter LLM filter
// =============================================================

type llmMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type llmRequest struct {
	Model       string       `json:"model"`
	Messages    []llmMessage `json:"messages"`
	Temperature float64      `json:"temperature"`
	MaxTokens   int          `json:"max_tokens"`
}

type llmResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

const systemPrompt = `You are a smart contract security auditor. You will receive a Solidity code snippet flagged by a regex scanner. Your job is to determine if the snippet contains a vulnerability that could enable a flash loan attack, oracle manipulation, or math precision error.

Respond with EXACTLY ONE WORD:
- VULNERABLE (if the snippet contains exploitable logic)
- SAFE (if the snippet is safe despite matching a pattern)

Do not explain. Do not add punctuation. One word only.`

// AskOpenRouter sends a snippet to the LLM and returns VULNERABLE or SAFE.
// Tries each model in LLMModels until one succeeds.
func AskOpenRouter(ctx context.Context, snippet string) (string, error) {
	apiKey := OpenRouterAPIKey
	if env := os.Getenv("OPENROUTER_API_KEY"); env != "" {
		apiKey = env
	}
	if apiKey == "" {
		return "", fmt.Errorf("OPENROUTER_API_KEY not set")
	}

	userPrompt := fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)

	body, _ := json.Marshal(llmRequest{
		Model:       LLMModels[0],
		Messages:    []llmMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userPrompt}},
		Temperature: 0,
		MaxTokens:   8,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		OpenRouterURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed llmResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("llm decode: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("llm error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("llm: no choices")
	}

	result := strings.TrimSpace(strings.ToUpper(parsed.Choices[0].Message.Content))
	if result == "VULNERABLE" || result == "SAFE" {
		return result, nil
	}
	return "", fmt.Errorf("llm: unexpected response %q", result)
}

// AskOpenRouterWithFallback tries each model in sequence.
func AskOpenRouterWithFallback(ctx context.Context, snippet string) (string, error) {
	var lastErr error
	for _, model := range LLMModels {
		body, _ := json.Marshal(llmRequest{
			Model:       model,
			Messages:    []llmMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)}},
			Temperature: 0,
			MaxTokens:   8,
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			OpenRouterURL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+OpenRouterAPIKey)

		c := &http.Client{Timeout: 30 * time.Second}
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var parsed llmResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			lastErr = err
			continue
		}
		if parsed.Error != nil || len(parsed.Choices) == 0 {
			lastErr = fmt.Errorf("model %s failed", model)
			continue
		}

		result := strings.TrimSpace(strings.ToUpper(parsed.Choices[0].Message.Content))
		if result == "VULNERABLE" || result == "SAFE" {
			return result, nil
		}
		lastErr = fmt.Errorf("model %s: unexpected %q", model, result)
	}
	return "", lastErr
}
