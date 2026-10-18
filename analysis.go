package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type etherscanSourceResult struct {
	SourceCode     string `json:"SourceCode"`
	ABI            string `json:"ABI"`
	ContractName   string `json:"ContractName"`
	Proxy          string `json:"Proxy"`
	Implementation string `json:"Implementation"`
}

type etherscanResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// =============================================================
// Programmatic Proxy Linking (Etherscan V2)
// =============================================================

type BaseScanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

// LinkProxyToImplementation forces Etherscan to link a proxy to its implementation.
func LinkProxyToImplementation(ctx context.Context, proxyAddress, implAddress string) error {
	data := url.Values{}
	data.Set("address", proxyAddress)
	data.Set("expectedimplementation", implAddress)

	endpoint := fmt.Sprintf("%s?chainid=%d&module=contract&action=verifyproxycontract&apikey=%s", 
		EtherscanBaseURL, EtherscanChainID, EtherscanAPIKey)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to construct request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http transfer layer failure: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var baseResp BaseScanResponse
	if err := json.Unmarshal(bodyBytes, &baseResp); err != nil {
		return fmt.Errorf("invalid json footprint payload: %w", err)
	}

	if baseResp.Status != "1" {
		return fmt.Errorf("etherscan tracking initialization rejected: %s", baseResp.Result)
	}

	guidToken := baseResp.Result
	
	statusEndpoint := fmt.Sprintf("%s?chainid=%d&module=contract&action=checkproxyverification&guid=%s&apikey=%s", 
		EtherscanBaseURL, EtherscanChainID, guidToken, EtherscanAPIKey)
	
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	timeout := time.After(60 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout limit reached while verifying target guid: %s", guidToken)
		case <-ticker.C:
			statusResp, err := client.Get(statusEndpoint)
			if err != nil {
				continue 
			}
			statusBytes, _ := io.ReadAll(statusResp.Body)
			statusResp.Body.Close()

			var pollResp BaseScanResponse
			if err := json.Unmarshal(statusBytes, &pollResp); err != nil {
				continue
			}

			switch pollResp.Result {
			case "Pending", "Awaiting confirmation":
				// Keep polling
			case "Pass", "Proxy contract verification successful", "SUCCESS":
				return nil
			default:
				if pollResp.Status == "1" || strings.Contains(pollResp.Result, "Already Verified") {
					return nil
				}
				return fmt.Errorf("verification dropped with error: %s", pollResp.Result)
			}
		}
	}
}

// =============================================================
// Source Resolution & Proxy Checks
// =============================================================

func ResolveImplementation(ctx context.Context, client *ethclient.Client, addr common.Address) common.Address {
	slot := common.HexToHash(EIP1967ImplementationSlot)
	raw, err := client.StorageAt(ctx, addr, slot, nil)
	if err != nil || len(raw) == 0 {
		return common.Address{}
	}
	impl := common.BytesToAddress(raw)
	if impl != (common.Address{}) {
		code, err := client.CodeAt(ctx, impl, nil)
		if err == nil && len(code) > 0 {
			return impl
		}
	}
	return common.Address{}
}

func UnwrapSource(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "{") && !strings.HasPrefix(raw, "{{") {
		return extractSourcesFromJSON(raw)
	}
	if strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		inner := raw[1 : len(raw)-1]
		return extractSourcesFromJSON(inner)
	}
	return raw
}

func extractSourcesFromJSON(jsonStr string) string {
	var parsed struct {
		Sources map[string]struct {
			Content string `json:"content"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, src := range parsed.Sources {
		sb.WriteString(src.Content)
		sb.WriteString("\n")
	}
	return sb.String()
}

// fetchRawSource performs the raw Etherscan API call.
func fetchRawSource(ctx context.Context, addr common.Address) (string, string, error) {
	q := url.Values{}
	q.Set("chainid", fmt.Sprintf("%d", EtherscanChainID))
	q.Set("module", "contract")
	q.Set("action", "getsourcecode")
	q.Set("address", addr.Hex())
	q.Set("apikey", EtherscanAPIKey)

	full := EtherscanBaseURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return "", "", err
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var parsed etherscanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", fmt.Errorf("etherscan decode: %w", err)
	}

	if parsed.Status == "0" {
		var errMsg string
		_ = json.Unmarshal(parsed.Result, &errMsg)
		return "", "", fmt.Errorf("%s", errMsg)
	}

	var results []etherscanSourceResult
	if err := json.Unmarshal(parsed.Result, &results); err != nil {
		return "", "", fmt.Errorf("etherscan result decode: %w", err)
	}
	if len(results) == 0 {
		return "", "", fmt.Errorf("etherscan: no result for %s", addr.Hex())
	}
	
	return results[0].SourceCode, results[0].ContractName, nil
}

func FetchVerifiedSource(ctx context.Context, client *ethclient.Client, addr common.Address) (string, string, error) {
	// Try to fetch normally
	src, name, err := fetchRawSource(ctx, addr)
	
	// If it fails with "not verified", attempt to link the proxy if this is a proxy
	if err != nil && strings.Contains(err.Error(), "not verified") {
		impl := ResolveImplementation(ctx, client, addr)
		if impl != (common.Address{}) {
			fmt.Printf("scanner[fix]: Attempting programmatic proxy linking for %s -> %s\n", addr.Hex(), impl.Hex())
			linkErr := LinkProxyToImplementation(ctx, addr.Hex(), impl.Hex())
			if linkErr == nil {
				// Wait for Etherscan indexers to update
				time.Sleep(5 * time.Second)
				// Retry fetching
				src, name, err = fetchRawSource(ctx, addr)
			}
		}
	}

	// Final check
	if err != nil {
		return "", "", err
	}
	if src == "" || strings.Contains(src, "not verified") {
		return "", "", fmt.Errorf("etherscan: source not verified for %s", addr.Hex())
	}

	// Rate limit sleep
	time.Sleep(400 * time.Millisecond)

	return UnwrapSource(src), name, nil
}

// ... [Keep Regex, ExtractDependencies, and RunRegexScan from previous version] ...
// (Make sure ExtractDependencies still has the safe library filter)
