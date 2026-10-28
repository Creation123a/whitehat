package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FourByteResponse mirrors the JSON structure returned by 4byte.directory
type FourByteResponse struct {
	Results []struct {
		TextSignature string `json:"text_signature"`
		HexSignature  string `json:"hex_signature"`
	} `json:"results"`
}

// ExtractAllSelectors scans raw EVM bytecode for PUSH4 opcodes (0x63)
// and returns a unique list of 4-byte selectors in hex format (without 0x).
func ExtractAllSelectors(bytecode []byte) []string {
	seen := make(map[string]bool)
	var out []string

	for i := 0; i+5 <= len(bytecode); i++ {
		// 0x63 is the PUSH4 opcode
		if bytecode[i] != 0x63 {
			continue
		}
		// Extract the 4 bytes following the opcode
		selBytes := bytecode[i+1 : i+5]
		selHex := hex.EncodeToString(selBytes)

		if !seen[selHex] {
			seen[selHex] = true
			out = append(out, selHex)
		}
	}
	return out
}

// ResolveSelectorToName queries 4byte.directory to find the human-readable
// function signature for a given 4-byte selector.
func ResolveSelectorToName(client *http.Client, selectorHex string) (string, error) {
	// 4byte.directory expects the selector with the 0x prefix
	baseURL := "https://www.4byte.directory/api/v1/signatures/"
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse 4byte URL: %w", err)
	}

	q := u.Query()
	q.Set("hex_signature", "0x"+selectorHex)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "base-spot-amm-scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("4byte HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var parsed FourByteResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("json decode failed: %w", err)
	}

	if len(parsed.Results) == 0 {
		return "", fmt.Errorf("no signature found")
	}

	// Return the first (most likely) text signature
	return parsed.Results[0].TextSignature, nil
}

// GetSelectorMap takes raw bytecode, extracts all PUSH4 selectors,
// and resolves them to human-readable names via 4byte.directory.
// It returns a map of selectorHex -> functionName.
func GetSelectorMap(ctx context.Context, bytecode []byte) map[string]string {
	selectors := ExtractAllSelectors(bytecode)
	result := make(map[string]string)

	// Create an HTTP client with a reasonable timeout
	client := &http.Client{Timeout: 10 * time.Second}

	log.Printf("scanner[selector]: Extracted %d unique PUSH4 selectors from bytecode", len(selectors))

	for i, sel := range selectors {
		// Check context cancellation
		select {
		case <-ctx.Done():
			log.Printf("scanner[selector]: Context cancelled, stopping selector resolution")
			return result
		default:
		}

		name, err := ResolveSelectorToName(client, sel)
		if err != nil {
			// Not all selectors will resolve (e.g., custom functions).
			// We log at a low level and continue.
			continue
		}

		result[sel] = name

		// 4byte.directory is a free public API. Add a small delay to be polite
		// and avoid rate-limiting (20 requests/second limit).
		if i < len(selectors)-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}

	log.Printf("scanner[selector]: Resolved %d/%d selectors to human-readable names", len(result), len(selectors))
	return result
}
