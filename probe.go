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

const (
	GroqAPIBase      = "https://api.groq.com/openai/v1/chat/completions"
	DefaultGroqModel = "llama-3.3-70b-versatile"
)

type groqRequest struct {
	Model       string        `json:"model"`
	Messages    []groqMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type groqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type groqResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

const systemPromptTemplate = `You are a smart contract security auditor.
You are analyzing a specific contract within a protocol.
Contract Role: %s
Contract Name: %s

Analyze the following Solidity snippet for economic vulnerabilities that can be exploited via flash loans, oracle manipulation, or mathematical precision errors.

Respond in EXACTLY this format:
VERDICT: <VULNERABLE|SAFE>
TYPE: <vulnerability type>
LOCATION: <line number or code fragment>
REASON: <one sentence>`

func groqAPIKey() string {
	for _, name := range []string{
		"GROQ_API_KEY",
		"OPENROUTER_API_KEY", // Fallback just in case
	} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// AskLLM sends a snippet with contract context to Groq.
func AskLLM(ctx context.Context, snippet, contractName, contractRole string) (string, error) {
	apiKey := groqAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("no Groq API key found in env (GROQ_API_KEY)")
	}

	model := os.Getenv("GROQ_MODEL")
	if model == "" {
		model = DefaultGroqModel
	}

	sysPrompt := fmt.Sprintf(systemPromptTemplate, contractRole, contractName)

	reqBody := groqRequest{
		Model: model,
		Messages: []groqMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)},
		},
		Temperature: 0,
	}

	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, GroqAPIBase, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed groqResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("groq decode: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("groq error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("groq: empty response")
	}

	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func ParseVerdict(response string) string {
	upper := strings.ToUpper(response)
	if idx := strings.Index(upper, "VERDICT:"); idx >= 0 {
		rest := strings.TrimSpace(upper[idx+len("VERDICT:"):])
		if strings.HasPrefix(rest, "VULNERABLE") {
			return "VULNERABLE"
		}
		if strings.HasPrefix(rest, "SAFE") {
			return "SAFE"
		}
	}
	return "UNKNOWN"
}
