package main

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// CallFrame is one node in a callTracer execution tree.
type CallFrame struct {
	From   string      `json:"from"`
	To     string      `json:"to"`
	Input  string      `json:"input"`
	Output string      `json:"output"`
	Error  string      `json:"error,omitempty"`
	Calls  []CallFrame `json:"calls,omitempty"`
}

// OracleTraceVerdict is the trace-based analysis result for one oracle.
type OracleTraceVerdict struct {
	Oracle      common.Address
	HasSpotRead bool
	Selectors   []string
	Pool        common.Address
	TracedAddrs []common.Address
	Shortlisted bool
}

const triageWorkers = 2

// TriageOracles traces each market's oracle price() call via
// debug_traceCall, walks the entire execution tree, and scans every
// downstream contract's bytecode for spot AMM selectors.
//
// This catches ChainlinkOracleV2 instances that read spot AMM state
// through an intermediate adapter contract — the exact pattern that
// bytecode-only scanning misses.
func TriageOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	markets []MorphoMarket,
) []MorphoMarket {

	verdicts := traceUniqueOracles(ctx, client, rpcClient, UniqueOracles(markets))

	var out []MorphoMarket
	for _, m := range markets {
		v, ok := verdicts[m.Oracle]
		if !ok || !v.Shortlisted {
			continue
		}
		m.Selectors = v.Selectors
		m.TracedPool = v.Pool
		out = append(out, m)
	}
	return out
}

func traceUniqueOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	oracles []common.Address,
) map[common.Address]OracleTraceVerdict {

	in := make(chan common.Address)
	out := make(chan OracleTraceVerdict)

	var wg sync.WaitGroup
	for i := 0; i < triageWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range in {
				v := traceOneOracle(ctx, client, rpcClient, o)
				select {
				case out <- v:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, o := range oracles {
			select {
			case in <- o:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	m := make(map[common.Address]OracleTraceVerdict)
	for v := range out {
		m[v.Oracle] = v
	}
	return m
}

func traceOneOracle(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	oracle common.Address,
) OracleTraceVerdict {

	v := OracleTraceVerdict{Oracle: oracle}

	frame, err := tracePriceCall(ctx, rpcClient, oracle)
	if err != nil || frame == nil {
		return fallbackBytecodeScan(ctx, client, oracle)
	}

	targets := make(map[common.Address]struct{})
	collectTargets(frame, targets)

	for a := range targets {
		v.TracedAddrs = append(v.TracedAddrs, a)
	}

	// Scan every downstream contract for spot AMM selectors. A contract
	// that implements getReserves() or slot0() is an AMM pool. If the
	// oracle's price() path reaches one, the oracle reads spot state.
	for addr := range targets {
		code, cerr := client.CodeAt(ctx, addr, nil)
		if cerr != nil || len(code) == 0 {
			continue
		}
		if containsPUSH4(code, SelGetReserves) {
			v.HasSpotRead = true
			v.Selectors = append(v.Selectors, "getReserves()@"+addr.Hex())
			if v.Pool == (common.Address{}) {
				v.Pool = addr
			}
		}
		if containsPUSH4(code, SelSlot0) {
			v.HasSpotRead = true
			v.Selectors = append(v.Selectors, "slot0()@"+addr.Hex())
			if v.Pool == (common.Address{}) {
				v.Pool = addr
			}
		}
	}

	// Robust feeds anywhere in the tree whitelist the market.
	for addr := range targets {
		code, cerr := client.CodeAt(ctx, addr, nil)
		if cerr != nil || len(code) == 0 {
			continue
		}
		if containsPUSH4(code, SelLatestRound) || containsPUSH4(code, SelObserve) {
			v.HasSpotRead = false
			v.Selectors = nil
			v.Pool = common.Address{}
			break
		}
	}

	v.Shortlisted = v.HasSpotRead
	return v
}

// tracePriceCall runs debug_traceCall with callTracer against the
// oracle's price() function at the latest block.
func tracePriceCall(
	ctx context.Context,
	rpcClient *rpc.Client,
	oracle common.Address,
) (*CallFrame, error) {

	callArg := map[string]interface{}{
		"to":   oracle.Hex(),
		"data": "0xa035b1fe", // price()
	}
	traceCfg := map[string]interface{}{
		"tracer": "callTracer",
	}

	var frame CallFrame
	if err := rpcClient.CallContext(ctx, &frame, "debug_traceCall",
		callArg, "latest", traceCfg); err != nil {
		return nil, err
	}
	return &frame, nil
}

func collectTargets(frame *CallFrame, out map[common.Address]struct{}) {
	if frame == nil || frame.To == "" {
		return
	}
	out[common.HexToAddress(frame.To)] = struct{}{}
	for i := range frame.Calls {
		collectTargets(&frame.Calls[i], out)
	}
}

// fallbackBytecodeScan is used when debug_traceCall is unavailable or
// the oracle reverts. Scans the oracle's own bytecode only — less
// accurate but better than dropping the market.
func fallbackBytecodeScan(
	ctx context.Context,
	client *ethclient.Client,
	oracle common.Address,
) OracleTraceVerdict {

	v := OracleTraceVerdict{Oracle: oracle}
	code, err := client.CodeAt(ctx, oracle, nil)
	if err != nil || len(code) == 0 {
		return v
	}

	hasSpot := false
	if containsPUSH4(code, SelGetReserves) {
		hasSpot = true
		v.Selectors = append(v.Selectors, "getReserves()@self")
	}
	if containsPUSH4(code, SelSlot0) {
		hasSpot = true
		v.Selectors = append(v.Selectors, "slot0()@self")
	}
	hasRobust := containsPUSH4(code, SelLatestRound) || containsPUSH4(code, SelObserve)

	v.HasSpotRead = hasSpot
	v.Shortlisted = hasSpot && !hasRobust
	return v
}

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
