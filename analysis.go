package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// CallFrame is one node in a callTracer execution tree.
//
// callTracer sets Error on the frame that reverted and does NOT
// return an RPC-level error for the trace call itself. Treating a
// reverted frame as "no spot reads" is a false negative — see
// traceOneOracle.
type CallFrame struct {
	From   string      `json:"from"`
	To     string      `json:"to"`
	Input  string      `json:"input"`
	Output string      `json:"output"`
	Error  string      `json:"error,omitempty"`
	Calls  []CallFrame `json:"calls,omitempty"`
}

// traceOutcome records what happened during the trace phase for one
// oracle. It is intentionally separate from Shortlisted so callers
// can distinguish "trace worked, oracle is clean" from "trace could
// not exercise the pricing path".
type traceOutcome int

const (
	outcomeTraceOK       traceOutcome = iota // trace walked cleanly
	outcomeTraceReverted                      // root frame reverted (msg.sender, stale feed, etc.)
	outcomeTraceError                         // debug_traceCall itself failed (provider, transport)
)

// OracleTraceVerdict is the trace-based analysis result for one oracle.
type OracleTraceVerdict struct {
	Oracle      common.Address
	HasSpotRead bool
	MixedSource bool             // both spot read AND robust feed present
	Selectors   []string
	Pools       []common.Address // every pool touched via getReserves()/slot0()
	TracedAddrs []common.Address
	Shortlisted bool

	outcome traceOutcome // unexported; aggregated into TriageStats
}

// TriageStats summarizes one TriageOracles pass. main.go logs it so
// a "0 shortlisted" result is never mistaken for a clean ecosystem
// when the real cause was transport / sender / staleness.
type TriageStats struct {
	Total         int
	TraceOK       int64
	TraceReverted int64
	TraceError    int64
	Shortlisted   int64
}

const triageWorkers = 1

// TriageOracles traces each market's oracle price() call via
// debug_traceCall, walks the execution tree, and inspects the
// calldata of every frame. A frame whose input starts with the
// getReserves() or slot0() selector is ground truth.
//
// Bug 1 policy: a Chainlink latestRoundData() anywhere in the tree
// does NOT whitelist the oracle. Mixed-source oracles — Chainlink
// for one leg, spot AMM for the other — are exactly the May 2025
// Aerodrome cUSDO/USDC pattern. They are shortlisted and flagged
// MixedSource.
func TriageOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	markets []MorphoMarket,
) ([]MorphoMarket, TriageStats) {

	verdicts, stats := traceUniqueOracles(ctx, client, rpcClient, markets)

	var out []MorphoMarket
	for _, m := range markets {
		v, ok := verdicts[m.Oracle]
		if !ok || !v.Shortlisted {
			continue
		}
		m.Selectors = v.Selectors
		m.TracedPools = v.Pools
		out = append(out, m)
	}
	stats.Shortlisted = int64(len(out))
	return out, stats
}

func traceUniqueOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	markets []MorphoMarket,
) (map[common.Address]OracleTraceVerdict, TriageStats) {

	// Dedupe by oracle, keeping the first market for collateral
	// context (used only by the bytecode fallback).
	seen := make(map[common.Address]MorphoMarket)
	var oracles []common.Address
	for _, m := range markets {
		if m.Oracle == (common.Address{}) {
			continue
		}
		if _, ok := seen[m.Oracle]; ok {
			continue
		}
		seen[m.Oracle] = m
		oracles = append(oracles, m.Oracle)
	}

	var (
		nOK       atomic.Int64
		nReverted atomic.Int64
		nError    atomic.Int64
	)

	in := make(chan common.Address)
	out := make(chan OracleTraceVerdict)

	var wg sync.WaitGroup
	for i := 0; i < triageWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range in {
				m := seen[o]
				v, oc := traceOneOracle(ctx, client, rpcClient, m)
				switch oc {
				case outcomeTraceOK:
					nOK.Add(1)
				case outcomeTraceReverted:
					nReverted.Add(1)
				case outcomeTraceError:
					nError.Add(1)
				}
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

	result := make(map[common.Address]OracleTraceVerdict)
	for v := range out {
		result[v.Oracle] = v
	}

	return result, TriageStats{
		Total:         len(oracles),
		TraceOK:       nOK.Load(),
		TraceReverted: nReverted.Load(),
		TraceError:    nError.Load(),
	}
}

func traceOneOracle(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	m MorphoMarket,
) (OracleTraceVerdict, traceOutcome) {

	v := OracleTraceVerdict{Oracle: m.Oracle}

	frame, err := tracePriceCall(ctx, rpcClient, m.Oracle)
	if err != nil || frame == nil {
		// Transport-level failure. Bytecode fallback is the best we
		// can do; flag the outcome so the caller can count it.
		fv := fallbackBytecodeScan(ctx, client, m.Oracle, m.CollateralAsset.Address)
		fv.outcome = outcomeTraceError
		return fv, outcomeTraceError
	}

	targets := make(map[common.Address]struct{})
	collectTargets(frame, targets)
	for a := range targets {
		v.TracedAddrs = append(v.TracedAddrs, a)
	}

	hasRobust := false
	walkFrames(frame, func(f *CallFrame) {
		if f.To == "" {
			return
		}
		to := common.HexToAddress(f.To)
		switch {
		case hasSelectorPrefix(f.Input, SelLatestRound),
			hasSelectorPrefix(f.Input, SelObserve):
			hasRobust = true
		case hasSelectorPrefix(f.Input, SelGetReserves):
			v.HasSpotRead = true
			v.Selectors = append(v.Selectors,
				"getReserves()@"+to.Hex())
			v.Pools = append(v.Pools, to)
		case hasSelectorPrefix(f.Input, SelSlot0):
			v.HasSpotRead = true
			v.Selectors = append(v.Selectors,
				"slot0()@"+to.Hex())
			v.Pools = append(v.Pools, to)
		}
	})

	v.Pools = dedupeAddresses(v.Pools)

	if hasRobust && v.HasSpotRead {
		v.MixedSource = true
		v.Selectors = append(v.Selectors, "MIXED_SOURCE")
	}

	// Issue A: a reverted root frame is not evidence of a clean
	// oracle. callTracer still populates sub-calls that executed
	// before the revert, so we keep whatever spot reads the partial
	// tree yielded. If the partial tree is empty AND the root
	// reverted, fall through to bytecode so an unexecuted branch
	// that contains getReserves()/slot0() is not silently missed.
	oc := outcomeTraceOK
	if frame.Error != "" {
		oc = outcomeTraceReverted
		if !v.HasSpotRead {
			fb := fallbackBytecodeScan(ctx, client,
				m.Oracle, m.CollateralAsset.Address)
			fb.Selectors = append(fb.Selectors,
				"TRACE_REVERTED:"+frame.Error)
			fb.outcome = oc
			return fb, oc
		}
		v.Selectors = append(v.Selectors,
			"TRACE_REVERTED:"+frame.Error)
	}

	v.Shortlisted = v.HasSpotRead
	v.outcome = oc
	return v, oc
}

// hasSelectorPrefix reports whether a hex-encoded calldata string
// starts with the given 4-byte selector.
//
// NOTE (Bug 5, accepted): getReserves() and slot0() take no arguments,
// so we cannot require argument bytes after the selector. The AMM-kind
// probe in simulation.go (detectAMMKind) is the real defence against
// 4-byte selector collisions.
func hasSelectorPrefix(input string, sel []byte) bool {
	if len(input) < 10 {
		return false
	}
	if input[0] == '0' && (input[1] == 'x' || input[1] == 'X') {
		input = input[2:]
	}
	if len(input) < 8 {
		return false
	}
	got := input[:8]
	want := fmt.Sprintf("%02x%02x%02x%02x", sel[0], sel[1], sel[2], sel[3])
	return strings.EqualFold(got, want)
}

// walkFrames visits every frame in the call tree, root first.
func walkFrames(f *CallFrame, visit func(*CallFrame)) {
	if f == nil {
		return
	}
	visit(f)
	for i := range f.Calls {
		walkFrames(&f.Calls[i], visit)
	}
}

// tracePriceCall runs debug_traceCall with callTracer against the
// oracle's price() function at the latest block.
//
// Issue B: from is set to the Morpho Blue contract so oracles that
// gate on msg.sender (a common defensive pattern) are exercised with
// the same caller they see on-chain. Defaulting to the zero address
// silently reverts those traces.
func tracePriceCall(
	ctx context.Context,
	rpcClient *rpc.Client,
	oracle common.Address,
) (*CallFrame, error) {

	callArg := map[string]interface{}{
		"from": MorphoBlueAddress.Hex(),
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

// fallbackBytecodeScan is used when debug_traceCall is unavailable,
// the oracle reverts with an empty partial tree, or the trace fails.
// Scans the oracle AND the collateral for spot selectors.
func fallbackBytecodeScan(
	ctx context.Context,
	client *ethclient.Client,
	oracle common.Address,
	collateral common.Address,
) OracleTraceVerdict {

	v := OracleTraceVerdict{Oracle: oracle}

	targets := []common.Address{oracle}
	if collateral != (common.Address{}) {
		targets = append(targets, collateral)
	}

	hasSpot := false
	hasRobust := false
	for _, t := range targets {
		code, err := client.CodeAt(ctx, t, nil)
		if err != nil || len(code) == 0 {
			continue
		}
		if containsPUSH4(code, SelGetReserves) {
			hasSpot = true
			v.Selectors = append(v.Selectors, "getReserves()@"+t.Hex())
			v.Pools = append(v.Pools, t)
		}
		if containsPUSH4(code, SelSlot0) {
			hasSpot = true
			v.Selectors = append(v.Selectors, "slot0()@"+t.Hex())
			v.Pools = append(v.Pools, t)
		}
		if containsPUSH4(code, SelLatestRound) || containsPUSH4(code, SelObserve) {
			hasRobust = true
		}
	}

	v.HasSpotRead = hasSpot
	if hasRobust && hasSpot {
		v.MixedSource = true
		v.Selectors = append(v.Selectors, "MIXED_SOURCE")
	}
	v.Shortlisted = hasSpot
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

// dedupeAddresses preserves order and removes duplicates.
func dedupeAddresses(in []common.Address) []common.Address {
	seen := make(map[common.Address]struct{}, len(in))
	out := in[:0]
	for _, a := range in {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
