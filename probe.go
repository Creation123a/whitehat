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
	GeminiAPIBase      = "https://generativelanguage.googleapis.com/v1beta/models"
	DefaultGeminiModel = "gemini-3.8-flash" // Or whatever model you are using
)

type geminiRequest struct {
	Contents          []geminiContent      `json:"contents"`
	SystemInstruction *geminiContent       `json:"systemInstruction,omitempty"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature      float64 `json:"temperature"`
	MaxOutputTokens  int     `json:"maxOutputTokens"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
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

func geminiAPIKey() string {
	for _, name := range []string{
		"OPENROUTER_API_KEY",
		"GEMINI_API_KEY",
		"GOOGLE_API_KEY",
	} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

func AskGemini(ctx context.Context, snippet, contractName, contractRole string) (string, error) {
	apiKey := geminiAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("no Gemini API key found")
	}

	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = DefaultGeminiModel
	}

	sysPrompt := fmt.Sprintf(systemPromptTemplate, contractRole, contractName)

	reqBody := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: sysPrompt}}},
		Contents: []geminiContent{{
			Role:  "user",
			Parts: []geminiPart{{Text: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)}},
		}},
		GenerationConfig: geminiGenerationConfig{
			Temperature:      0,
			MaxOutputTokens:  512, // FIXED: Increased from 256 to prevent truncation
			ResponseMimeType: "text/plain",
		},
	}

	body, _ := json.Marshal(reqBody)
	fullURL := fmt.Sprintf("%s/%s:generateContent", GeminiAPIBase, model)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed geminiResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("gemini decode: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("gemini error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty response")
	}

	return strings.TrimSpace(parsed.Candidates[0].Content.Parts[0].Text), nil
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
