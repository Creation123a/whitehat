package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// =============================================================
// Core types
// =============================================================

type AssetInfo struct {
	Address  string
	Symbol   string
	Name     string
	Decimals uint8
}

type Protocol struct {
	Name     string
	Slug     string
	Category string
	TVLUSD   float64
}

// =============================================================
// DefiLlama wire types
// =============================================================

type defiLlamaProtocol struct {
	Name      string             `json:"name"`
	Slug      string             `json:"slug"`
	TVL       float64            `json:"tvl"`
	Category  string             `json:"category"`
	Chains    []string           `json:"chains"`
	ChainTvls map[string]float64 `json:"chainTvls"`
}

// =============================================================
// Phase 1: DefiLlama discovery + filter
// =============================================================

func DiscoverProtocols(ctx context.Context, category string) ([]Protocol, error) {
	if !TargetCategories[category] {
		return nil, fmt.Errorf("invalid category %q", category)
	}

	raw, err := httpGet(ctx, DefiLlamaProtocolsURL)
	if err != nil {
		return nil, fmt.Errorf("defillama fetch: %w", err)
	}

	var all []defiLlamaProtocol
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("defillama decode: %w", err)
	}

	var out []Protocol
	for _, p := range all {
		if !containsString(p.Chains, DefiLlamaBaseChain) {
			continue
		}
		baseTVL, ok := p.ChainTvls[DefiLlamaBaseChain]
		if !ok {
			baseTVL = p.TVL
		}
		if baseTVL < MinTVLUSD || baseTVL > MaxTVLUSD {
			continue
		}
		if p.Category != category {
			continue
		}
		out = append(out, Protocol{
			Name:     p.Name,
			Slug:     p.Slug,
			Category: p.Category,
			TVLUSD:   baseTVL,
		})
	}
	return out, nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
