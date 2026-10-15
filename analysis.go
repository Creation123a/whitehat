package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// =============================================================
// Phase 2: SQD MCP address resolution + Anvil bytecode scan
// =============================================================
//
// SQD exposes its Portal tools through an MCP server at
// https://portal.sqd.dev/mcp. The official Go MCP SDK handles
// JSON-RPC framing, streamable HTTP, and protocol negotiation.
// The `portal_resolve_entity` tool turns a protocol name into a
// contract address on Base.
//
// The bytecode scan half of Phase 2 is unchanged: it uses the
// Anvil fork for eth_getCode and looks for pricing selectors.
// =============================================================

// sqdMCPClient wraps the official Go MCP SDK client with a lazily
// initialized, reusable session against the SQD Portal.
type sqdMCPClient struct {
	mu      sync.Mutex
	client  *mcp.Client
	session *mcp.ClientSession
	closed  bool
}

var globalSQD sqdMCPClient

// connect establishes or reuses the MCP session to SQD. Safe for
// concurrent callers; the underlying SDK session serializes
// requests internally.
func (c *sqdMCPClient) connect(ctx context.Context) (*mcp.ClientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("sqd mcp client already closed")
	}
	if c.session != nil {
		return c.session, nil
	}
	if c.client == nil {
		c.client = mcp.NewClient(
			&mcp.Implementation{
				Name:    "base-spot-amm-scanner",
				Version: "1.0.0",
			},
			nil,
		)
	}

	transport := &mcp.StreamableClientTransport{
		Endpoint: SQDPortalMCPURL,
	}

	// Bound the initial handshake so a hung SQD endpoint does not
	// stall the whole pipeline.
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	session, err := c.client.Connect(dialCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("sqd mcp connect: %w", err)
	}
	c.session = session
	return session, nil
}

// close terminates the MCP session and marks the client closed.
func (c *sqdMCPClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.session != nil {
		_ = c.session.Close()
		c.session = nil
	}
}

// CloseSQD is called by main.go via defer to cleanly terminate the
// MCP session before the process exits.
func CloseSQD() {
	globalSQD.close()
}

// ResolveProtocolAddress resolves a protocol name to a Base
// contract address via SQD's portal_resolve_entity MCP tool.
//
// Tries several `kind` values in order because DefiLlama protocol
// names are not always classified the same way SQD's resolver
// expects. The first successful hit wins.
func ResolveProtocolAddress(ctx context.Context, name string) (common.Address, error) {
	session, err := globalSQD.connect(ctx)
	if err != nil {
		return common.Address{}, err
	}

	// Per-call timeout so one bad protocol cannot stall the run.
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	kinds := []string{"contract", "token", ""}
	var lastErr error
	for _, kind := range kinds {
		addr, err := sqdResolveOnce(callCtx, session, name, kind)
		if err == nil && addr != (common.Address{}) {
			return addr, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return common.Address{}, fmt.Errorf("sqd mcp resolve %q: %w", name, lastErr)
	}
	return common.Address{}, fmt.Errorf("sqd mcp: no Base address for %q", name)
}

// sqdResolveOnce performs one portal_resolve_entity call and
// extracts the first valid Base address from the response.
func sqdResolveOnce(
	ctx context.Context,
	session *mcp.ClientSession,
	name string,
	kind string,
) (common.Address, error) {

	args := map[string]any{
		"query":   name,
		"network": "base-mainnet",
		"limit":   10,
	}
	if kind != "" {
		args["kind"] = kind
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "portal_resolve_entity",
		Arguments: args,
	})
	if err != nil {
		return common.Address{}, err
	}
	if res == nil {
		return common.Address{}, fmt.Errorf("nil tool result")
	}
	if res.IsError {
		return common.Address{}, fmt.Errorf("tool reported error")
	}

	// Preferred: structured content.
	if res.StructuredContent != nil {
		if addr := findAddressInAny(res.StructuredContent); addr != (common.Address{}) {
			return addr, nil
		}
	}

	// Fallback: text content that may hold JSON.
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc != nil {
			sb.WriteString(tc.Text)
		}
	}
	if sb.Len() > 0 {
		var parsed any
		if err := json.Unmarshal([]byte(sb.String()), &parsed); err == nil {
			if addr := findAddressInAny(parsed); addr != (common.Address{}) {
				return addr, nil
			}
		}
	}

	return common.Address{}, fmt.Errorf("no address in response")
}

// findAddressInAny normalizes an arbitrary value to JSON-decoded
// form (map/slice/string) and searches recursively for the first
// plausible Base contract address.
func findAddressInAny(v any) common.Address {
	normalized := normalizeJSON(v)
	return walkForAddress(normalized)
}

// normalizeJSON converts SDK structs into plain map[string]any /
// []any by round-tripping through encoding/json. Values that are
// already JSON-native are returned unchanged.
func normalizeJSON(v any) any {
	if v == nil {
		return nil
	}
	switch v.(type) {
	case map[string]any, []any, string, float64, float32,
		int, int64, bool:
		return v
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// addressKeys are field names SQD may use for a resolved address.
// Ordered by preference.
var addressKeys = []string{
	"address",
	"contract",
	"contractAddress",
	"contract_address",
	"token_address",
	"tokenAddress",
}

// walkForAddress recursively searches a JSON-decoded value for the
// first string that parses as a non-zero EVM address, preferring
// values stored under one of the addressKeys.
func walkForAddress(v any) common.Address {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range addressKeys {
			if raw, ok := x[k]; ok {
				if a := asAddress(raw); a != (common.Address{}) {
					return a
				}
			}
		}
		for _, raw := range x {
			if a := walkForAddress(raw); a != (common.Address{}) {
				return a
			}
		}
	case []any:
		for _, raw := range x {
			if a := walkForAddress(raw); a != (common.Address{}) {
				return a
			}
		}
	case string:
		return asAddress(x)
	}
	return common.Address{}
}

// asAddress returns the address encoded by s, or the zero address
// if s is not a valid 20-byte hex string.
func asAddress(v any) common.Address {
	s, ok := v.(string)
	if !ok {
		return common.Address{}
	}
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") || len(s) != 42 {
		return common.Address{}
	}
	a := common.HexToAddress(s)
	if a == (common.Address{}) {
		return common.Address{}
	}
	return a
}

// =============================================================
// Bytecode scan via the Anvil fork (unchanged from prior version)
// =============================================================

// ScanPricingContracts fetches bytecode via Anvil and returns the
// protocol address if it contains any pricing selector.
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
// PUSH4 scanner (unchanged)
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
