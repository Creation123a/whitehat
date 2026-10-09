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

type CallFrame struct {
	From   string      `json:"from"`
	To     string      `json:"to"`
	Input  string      `json:"input"`
	Output string      `json:"output"`
	Error  string      `json:"error,omitempty"`
	Calls  []CallFrame `json:"calls,omitempty"`
}

type traceOutcome int

const (
	outcomeTraceOK traceOutcome = iota
	outcomeTraceReverted
	outcomeTraceError
)

type OracleTraceVerdict struct {
	Oracle      common.Address
	HasSpotRead bool
	MixedSource bool
	Selectors   []string
	Pools       []common.Address
	Shortlisted bool
	outcome     traceOutcome
}

type TriageStats struct {
	Total         int
	TraceOK       int64
	TraceReverted int64
	TraceError    int64
	Shortlisted   int64
}

const triageWorkers = 2

// TriageOracles returns:
//   - a map from market ID to the pools the oracle touched, for
//     markets whose oracle has at least one spot read
//   - aggregate stats
//
// Markets not in the map are considered not shortlisted.
func TriageOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	markets []MorphoMarket,
) (map[string]OracleTraceVerdict, TriageStats) {

	verdicts, stats := traceUniqueOracles(ctx, client, rpcClient, markets)

	out := make(map[string]OracleTraceVerdict)
	var n int64
	for _, m := range markets {
		v, ok := verdicts[m.Oracle]
		if !ok || !v.Shortlisted {
			continue
		}
		m.Selectors = v.Selectors
		m.TracedPools = v.Pools
		out[m.MarketID] = v
		n++
	}
	stats.Shortlisted = n
	return out, stats
}

func traceUniqueOracles(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	markets []MorphoMarket,
) (map[common.Address]OracleTraceVerdict, TriageStats) {

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

	go func() { wg.Wait(); close(out) }()

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
		fv := fallbackBytecodeScan(ctx, client, m.Oracle, m.CollateralAsset.Address)
		fv.outcome = outcomeTraceError
		return fv, outcomeTraceError
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
			v.Selectors = append(v.Selectors, "getReserves()@"+to.Hex())
			v.Pools = append(v.Pools, to)
		case hasSelectorPrefix(f.Input, SelSlot0):
			v.HasSpotRead = true
			v.Selectors = append(v.Selectors, "slot0()@"+to.Hex())
			v.Pools = append(v.Pools, to)
		}
	})
	v.Pools = dedupeAddresses(v.Pools)

	if hasRobust && v.HasSpotRead {
		v.MixedSource = true
		v.Selectors = append(v.Selectors, "MIXED_SOURCE")
	}

	oc := outcomeTraceOK
	if frame.Error != "" {
		oc = outcomeTraceReverted
		if !v.HasSpotRead {
			fb := fallbackBytecodeScan(ctx, client, m.Oracle, m.CollateralAsset.Address)
			fb.Selectors = append(fb.Selectors, "TRACE_REVERTED:"+frame.Error)
			fb.outcome = oc
			return fb, oc
		}
		v.Selectors = append(v.Selectors, "TRACE_REVERTED:"+frame.Error)
	}

	v.Shortlisted = v.HasSpotRead
	v.outcome = oc
	return v, oc
}

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
	return strings.EqualFold(input[:8],
		fmt.Sprintf("%02x%02x%02x%02x", sel[0], sel[1], sel[2], sel[3]))
}

func walkFrames(f *CallFrame, visit func(*CallFrame)) {
	if f == nil {
		return
	}
	visit(f)
	for i := range f.Calls {
		walkFrames(&f.Calls[i], visit)
	}
}

func tracePriceCall(ctx context.Context, rpcClient *rpc.Client, oracle common.Address) (*CallFrame, error) {
	callArg := map[string]interface{}{
		"from": MorphoBlueAddress.Hex(),
		"to":   oracle.Hex(),
		"data": "0xa035b1fe",
	}
	traceCfg := map[string]interface{}{"tracer": "callTracer"}
	var frame CallFrame
	if err := rpcClient.CallContext(ctx, &frame, "debug_traceCall",
		callArg, "latest", traceCfg); err != nil {
		return nil, err
	}
	return &frame, nil
}

func fallbackBytecodeScan(ctx context.Context, client *ethclient.Client, oracle, collateral common.Address) OracleTraceVerdict {
	v := OracleTraceVerdict{Oracle: oracle}
	targets := []common.Address{oracle}
	if collateral != (common.Address{}) {
		targets = append(targets, collateral)
	}
	hasSpot, hasRobust := false, false
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
