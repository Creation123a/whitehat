package main

import (
	"bytes"
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// =============================================================
// Differential fork probing for non-Morpho protocols
// =============================================================

type DivergentFunc struct {
	SelectorHex   string `json:"selector"`
	FunctionName  string `json:"function,omitempty"`
	CleanOutput   string `json:"clean_output"`
	MutatedOutput string `json:"mutated_output"`
	Pool          string `json:"pool"`
}

type ProbeVerdict struct {
	Protocol       common.Address
	Name           string
	Category       string
	TVLUSD         float64
	AMMDependent   bool
	DivergentFuncs []DivergentFunc
	ControlClean   bool
	Pools          []common.Address
	Reason         string
	Skipped        bool
	SkipReason     string
}

// callableRead is a selector/args combination that returns data on a
// clean fork and is therefore a candidate for differential probing.
type callableRead struct {
	selector []byte
	args     []byte
	baseline []byte
}

// ProbeProtocol runs differential fork probing on a single protocol.
//
// Steps:
//  1. Fetch bytecode; skip if absent.
//  2. Scan bytecode for PUSH20 candidates; probe each for AMM
//     function signatures; the survivors are the pool set.
//  3. Scan bytecode for PUSH4 selectors; try each with no args and
//     with a 32-byte arg of 1e18; anything that returns data is a
//     callable read. Record baseline output.
//  4. For each pool: snapshot → mutate → re-call every callable →
//     record divergence → revert.
//  5. Control: mutate an unrelated AMM and re-call; if the same
//     callables also move, discard them (timestamp/block dependence).
//
// The verdict is safe to consume even when probing fails: check
// Skipped / SkipReason rather than treating zero divergence as
// "clean" without confirming the probe ran.
func ProbeProtocol(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	proto Protocol,
) ProbeVerdict {

	v := ProbeVerdict{
		Protocol: proto.Address,
		Name:     proto.Name,
		Category: proto.Category,
		TVLUSD:   proto.TotalAssetsUSD,
	}

	if proto.Address == (common.Address{}) {
		v.Skipped = true
		v.SkipReason = "no_address_resolved"
		return v
	}

	code, err := client.CodeAt(ctx, proto.Address, nil)
	if err != nil {
		v.Skipped = true
		v.SkipReason = "code_fetch_failed"
		return v
	}
	if len(code) == 0 {
		v.Skipped = true
		v.SkipReason = "no_bytecode"
		return v
	}

	pools := discoverProtocolPools(ctx, client, proto.Address, code)
	if len(pools) == 0 {
		v.Skipped = true
		v.SkipReason = "no_amm_pool_referenced"
		return v
	}
	v.Pools = pools

	callables := enumerateCallableReads(ctx, client, proto.Address, code)
	if len(callables) == 0 {
		v.Skipped = true
		v.SkipReason = "no_callable_reads"
		return v
	}

	for _, pool := range pools {
		kind := detectAMMKind(ctx, client, pool)
		if kind == "" {
			continue
		}
		snap, err := takeSnapshot(ctx, rpcClient)
		if err != nil {
			continue
		}
		if _, err := mutatePool(ctx, client, rpcClient, pool, kind); err != nil {
			_ = revertSnapshot(context.Background(), rpcClient, snap)
			continue
		}
		for _, c := range callables {
			raw, err := callRaw(ctx, client, proto.Address, c.selector, c.args)
			if err != nil {
				continue
			}
			if !bytes.Equal(raw, c.baseline) {
				v.DivergentFuncs = append(v.DivergentFuncs, DivergentFunc{
					SelectorHex:   common.Bytes2Hex(c.selector),
					FunctionName:  labelSelector(c.selector),
					CleanOutput:   common.Bytes2Hex(c.baseline),
					MutatedOutput: common.Bytes2Hex(raw),
					Pool:          pool.Hex(),
				})
			}
		}
		_ = revertSnapshot(context.Background(), rpcClient, snap)
	}

	// Control mutation: discard divergences that also move under an
	// unrelated AMM mutation (filters timestamp/block dependence).
	controlPool := findControlPool(ctx, client, pools)
	if controlPool != (common.Address{}) && len(v.DivergentFuncs) > 0 {
		v.ControlClean = runControlCheck(ctx, client, rpcClient,
			proto.Address, callables, controlPool)
	} else {
		v.ControlClean = true
	}

	if !v.ControlClean {
		v.DivergentFuncs = nil
		v.Reason = "control_mutation_also_moved_functions"
		return v
	}

	v.AMMDependent = len(v.DivergentFuncs) > 0
	if !v.AMMDependent {
		v.Reason = "no_amm_dependence_detected"
	}
	return v
}

// runControlCheck mutates controlPool and re-calls each callable. If
// any callable moves, the protocol's read path is not AMM-specific.
func runControlCheck(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	target common.Address,
	callables []callableRead,
	controlPool common.Address,
) bool {

	kind := detectAMMKind(ctx, client, controlPool)
	if kind == "" {
		return true
	}
	snap, err := takeSnapshot(ctx, rpcClient)
	if err != nil {
		return true
	}
	defer func() {
		_ = revertSnapshot(context.Background(), rpcClient, snap)
	}()

	if _, err := mutatePool(ctx, client, rpcClient, controlPool, kind); err != nil {
		return true
	}
	for _, c := range callables {
		raw, err := callRaw(ctx, client, target, c.selector, c.args)
		if err != nil {
			continue
		}
		if !bytes.Equal(raw, c.baseline) {
			return false
		}
	}
	return true
}

// enumerateCallableReads scans bytecode for PUSH4 selectors and tries
// each with no args and with a 32-byte arg of 1e18. Anything that
// returns data is retained as a callable read.
func enumerateCallableReads(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
	code []byte,
) []callableRead {

	candidates := extractPUSH4Selectors(code)
	argE18 := common.LeftPadBytes(big.NewInt(1e18).Bytes(), 32)

	var out []callableRead
	for _, sel := range candidates {
		for _, args := range [][]byte{nil, argE18} {
			raw, err := callRaw(ctx, client, addr, sel, args)
			if err != nil || len(raw) == 0 {
				continue
			}
			out = append(out, callableRead{
				selector: sel,
				args:     args,
				baseline: raw,
			})
			break
		}
	}
	return out
}

// extractPUSH4Selectors scans bytecode for PUSH4 opcodes (0x63) and
// returns the unique 4-byte values.
func extractPUSH4Selectors(code []byte) [][]byte {
	seen := make(map[string]bool)
	var out [][]byte
	for i := 0; i+5 <= len(code); i++ {
		if code[i] != 0x63 {
			continue
		}
		sel := code[i+1 : i+5]
		key := string(sel)
		if seen[key] {
			continue
		}
		seen[key] = true
		cp := make([]byte, 4)
		copy(cp, sel)
		out = append(out, cp)
	}
	return out
}

// discoverProtocolPools scans protocol bytecode for PUSH20 addresses
// and probes each for AMM function signatures.
func discoverProtocolPools(
	ctx context.Context,
	client *ethclient.Client,
	protocolAddr common.Address,
	code []byte,
) []common.Address {

	candidates := extractPUSH20Candidates(code)
	var out []common.Address
	for _, c := range candidates {
		if c == protocolAddr {
			continue
		}
		if detectAMMKind(ctx, client, c) != "" {
			out = append(out, c)
		}
	}
	return out
}

// findControlPool returns a known Base AMM that is not in the
// protocol's referenced set, for the control mutation. If the
// reference pool is itself the control candidate, the control check
// is disabled by returning the zero address.
func findControlPool(
	ctx context.Context,
	client *ethclient.Client,
	excluded []common.Address,
) common.Address {

	// Well-known Base Aerodrome WETH/USDC pool. Unrelated to the vast
	// majority of protocol bytecode; safe as a control target.
	ctrl := common.HexToAddress("0xd0b53D9277642d899DF5C87A3966A349A798F224")
	if detectAMMKind(ctx, client, ctrl) == "" {
		return common.Address{}
	}
	for _, e := range excluded {
		if e == ctrl {
			return common.Address{}
		}
	}
	return ctrl
}

// callRaw performs an eth_call and returns the raw output bytes.
func callRaw(
	ctx context.Context,
	client *ethclient.Client,
	to common.Address,
	selector []byte,
	args []byte,
) ([]byte, error) {

	data := make([]byte, 0, len(selector)+len(args))
	data = append(data, selector...)
	data = append(data, args...)
	msg := ethereum.CallMsg{To: &to, Data: data}
	return client.CallContract(ctx, msg, nil)
}

// labelSelector maps a few well-known selectors to human names.
func labelSelector(sel []byte) string {
	if len(sel) != 4 {
		return ""
	}
	switch common.Bytes2Hex(sel) {
	case "01e1a05f":
		return "totalAssets()"
	case "18160ddd":
		return "totalSupply()"
	case "07a2d324":
		return "convertToAssets(uint256)"
	case "0902f1ac":
		return "getReserves()"
	case "3850c7bd":
		return "slot0()"
	case "a035b1fe":
		return "price()"
	case "bb7b8b80":
		return "get_virtual_price()"
	case "50d25bcd":
		return "latestAnswer()"
	case "feaf968c":
		return "latestRoundData()"
	}
	return ""
}
