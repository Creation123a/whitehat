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
// Phase 4: Google AI Studio (Gemini API) LLM filter
// =============================================================

// Gemini API endpoint. Model is configurable via GEMINI_MODEL env.
const (
	GeminiAPIBase = "https://generativelanguage.googleapis.com/v1beta/models"
	DefaultGeminiModel = "gemini-2.0-flash"
)

// geminiRequest is the generateContent request body.
type geminiRequest struct {
	Contents         []geminiContent `json:"contents"`
	SystemInstruction *geminiContent `json:"systemInstruction,omitempty"`
	GenerationConfig geminiGenerationConfig `json:"generationConfig"`
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

// geminiResponse is the generateContent response body.
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

// systemPrompt instructs the model to return a structured verdict
// instead of a single word, with vulnerability location and type.
const systemPrompt = `You are a smart contract security auditor.

You will receive a Solidity code snippet flagged by a regex scanner. Your job is to determine:
1. Is this snippet VULNERABLE or SAFE?
2. If VULNERABLE, what specific vulnerability type is it?
3. Where exactly in the snippet is the vulnerability (line number or code fragment)?

Respond in EXACTLY this format (no markdown, no extra text):
VERDICT: <VULNERABLE|SAFE>
TYPE: <vulnerability type, e.g. spot-price-oracle, division-before-multiplication, stale-oracle, decimal-mismatch, read-only-reentrancy, lp-valuation, none>
LOCATION: <line number or the exact vulnerable code fragment, or "none">
REASON: <one sentence explaining why>

Do not over-explain. Be precise.`

// AskGemini sends a snippet to Google AI Studio and returns a
// structured verdict string.
func AskGemini(ctx context.Context, snippet string) (string, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("GOOGLE_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY or GOOGLE_API_KEY not set")
	}

	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = DefaultGeminiModel
	}

	// Build request body.
	reqBody := geminiRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: systemPrompt}},
		},
		Contents: []geminiContent{{
			Role:  "user",
			Parts: []geminiPart{{Text: fmt.Sprintf("Snippet:\n```solidity\n%s\n```", snippet)}},
		}},
		GenerationConfig: geminiGenerationConfig{
			Temperature:      0,
			MaxOutputTokens:  256,
			ResponseMimeType: "text/plain",
		},
	}

	body, _ := json.Marshal(reqBody)

	// URL: /v1beta/models/{model}:generateContent
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
		return "", fmt.Errorf("gemini decode: %w (body: %s)", err, string(raw))
	}

	if parsed.Error != nil {
		return "", fmt.Errorf("gemini error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if len(parsed.Candidates) == 0 {
		return "", fmt.Errorf("gemini: no candidates")
	}
	if len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty parts (finishReason: %s)", parsed.Candidates[0].FinishReason)
	}

	text := strings.TrimSpace(parsed.Candidates[0].Content.Parts[0].Text)
	if text == "" {
		return "", fmt.Errorf("gemini: empty response text")
	}
	return text, nil
}

// AskGeminiWithFallback wraps AskGemini with a retry on the
// alternate env key name. This is a no-op if the primary key works.
func AskGeminiWithFallback(ctx context.Context, snippet string) (string, error) {
	// Primary attempt.
	result, err := AskGemini(ctx, snippet)
	if err == nil {
		return result, nil
	}

	// If the error mentions the API key, retry with the alternate
	// env var name. Otherwise return the original error.
	if strings.Contains(err.Error(), "not set") {
		altKey := os.Getenv("GOOGLE_AI_STUDIO_KEY")
		if altKey != "" {
			os.Setenv("GEMINI_API_KEY", altKey)
			return AskGemini(ctx, snippet)
		}
	}
	return "", err
}
