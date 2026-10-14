package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================
// Phase 2: SQD address resolution + Anvil bytecode fetch
// =============================================================

type sqdResolveRequest struct {
	Network string `json:"network"`
	Kind    string `json:"kind"`
	Query   string `json:"query"`
	Limit   int    `json:"limit"`
}

type sqdResolveMatch struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	ChainID int    `json:"chainId"`
}

type sqdResolveResponse struct {
	Items []sqdResolveMatch `json:"items"`
}

// ResolveProtocolAddress calls SQD portal_resolve_entity to get the
// contract address(es) for a protocol name on Base.
func ResolveProtocolAddress(ctx context.Context, name string) (common.Address, error) {
	body, _ := json.Marshal(sqdResolveRequest{
		Network: "base-mainnet",
		Kind:    "contract",
		Query:   name,
		Limit:   5,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		SQDPortalURL+"/resolve", bytes.NewReader(body))
	if err != nil {
		return common.Address{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return common.Address{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return common.Address{}, fmt.Errorf("sqd HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var parsed sqdResolveResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return common.Address{}, fmt.Errorf("sqd decode: %w", err)
	}

	for _, m := range parsed.Items {
		if m.Address == "" {
			continue
		}
		addr := common.HexToAddress(m.Address)
		if addr == (common.Address{}) {
			continue
		}
		return addr, nil
	}
	return common.Address{}, fmt.Errorf("sqd: no address for %q", name)
}

// ScanPricingContracts fetches bytecode via Anvil and returns the
// addresses that contain any pricing selector.
func ScanPricingContracts(
	ctx context.Context,
	client *ethclient.Client,
	proto Protocol,
) ([]common.Address, error) {

	if proto.Address == (common.Address{}) {
		return nil, fmt.Errorf("no address for %s", proto.Name)
	}

	code, err := client.CodeAt(ctx, proto.Address, nil)
	if err != nil {
		return nil, fmt.Errorf("code fetch: %w", err)
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("no bytecode at %s", proto.Address.Hex())
	}

	// Collect all selectors present in the bytecode.
	hasPricing := false
	for _, sel := range []struct {
		name string
		data []byte
	}{
		{"getAssetPrice", SelGetAssetPrice},
		{"getUnderlyingPrice", SelGetUnderlyingPrice},
		{"getReserves", SelGetReserves},
		{"slot0", SelSlot0},
		{"get_virtual_price", SelGetVirtualPrice},
		{"latestRoundData", SelLatestRound},
		{"latestAnswer", SelLatestAnswer},
		{"observe", SelObserve},
	} {
		if containsPUSH4(code, sel.data) {
			hasPricing = true
			break
		}
	}

	if !hasPricing {
		return nil, fmt.Errorf("no pricing selectors in %s", proto.Address.Hex())
	}

	return []common.Address{proto.Address}, nil
}

// =============================================================
// PUSH4 scanner (reused by Phase 2)
// =============================================================

func containsPUSH4(code, sel []byte) bool {
	if len(sel) != 4 {
		return false
	}
	for i := 0; i+5 <= len(code); i++ {
		if code[i] != 0x63 {
			continue
		}
		if code[i+1] == sel[0] && code[i+2] == sel[1] &&
			code[i+3] == sel[2] && code[i+4] == sel[3] {
			return true
		}
	}
	return false
}

// =============================================================
// Utility
// =============================================================

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
