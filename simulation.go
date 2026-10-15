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

const (
	GeminiAPIBase      = "https://generativelanguage.googleapis.com/v1beta/models"
	DefaultGeminiModel = "gemini-2.0-flash"
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

// geminiAPIKey returns the first non-empty API key from the
// environment. Checks OPENROUTER_API_KEY first so the workflow's
// existing secret works unchanged.
func geminiAPIKey() string {
	for _, name := range []string{
		"OPENROUTER_API_KEY",
		"GEMINI_API_KEY",
		"GOOGLE_API_KEY",
		"GOOGLE_AI_STUDIO_KEY",
	} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// AskGemini sends a snippet to Google AI Studio and returns the
// raw structured verdict string.
func AskGemini(ctx context.Context, snippet string) (string, error) {
	apiKey := geminiAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("no Gemini API key found in env (OPENROUTER_API_KEY, GEMINI_API_KEY, GOOGLE_API_KEY, GOOGLE_AI_STUDIO_KEY)")
	}

	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = DefaultGeminiModel
	}

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

// AskGeminiWithFallback is the entry point used by main.go.
// Named to match the call site exactly.
func AskGeminiWithFallback(ctx context.Context, snippet string) (string, error) {
	return AskGemini(ctx, snippet)
}

// ParseVerdict extracts VULNERABLE / SAFE / UNKNOWN from a
// structured Gemini response. Looks for "VERDICT: <word>" first,
// then falls back to scanning the first line.
func ParseVerdict(response string) string {
	upper := strings.ToUpper(response)

	// Preferred: exact "VERDICT: VULNERABLE" or "VERDICT: SAFE".
	if idx := strings.Index(upper, "VERDICT:"); idx >= 0 {
		rest := upper[idx+len("VERDICT:"):]
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "VULNERABLE") {
			return "VULNERABLE"
		}
		if strings.HasPrefix(rest, "SAFE") {
			return "SAFE"
		}
	}

	// Fallback: first non-empty line containing either word.
	for _, line := range strings.Split(upper, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "VULNERABLE") {
			return "VULNERABLE"
		}
		if strings.Contains(line, "SAFE") {
			return "SAFE"
		}
	}
	return "UNKNOWN"
}
