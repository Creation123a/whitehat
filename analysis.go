package main

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// OracleVerdict is the static analysis result for one oracle.
type OracleVerdict struct {
	Oracle        common.Address
	HasSpotRead   bool
	HasRobustFeed bool
	Selectors     []string
	Whitelisted   bool
	Shortlisted   bool
}

const triageWorkers = 4

// TriageOracles scans each market's oracle bytecode, keeps only markets
// whose oracle reads spot AMM state and has no robust feed.
func TriageOracles(
	ctx context.Context,
	client *ethclient.Client,
	markets []MorphoMarket,
) []MorphoMarket {

	verdicts := scanUniqueOracles(ctx, client, UniqueOracles(markets))

	var out []MorphoMarket
	for _, m := range markets {
		v, ok := verdicts[m.Oracle]
		if !ok || !v.Shortlisted {
			continue
		}
		m.Selectors = v.Selectors
		out = append(out, m)
	}
	return out
}

func scanUniqueOracles(
	ctx context.Context,
	client *ethclient.Client,
	oracles []common.Address,
) map[common.Address]OracleVerdict {

	in := make(chan common.Address)
	out := make(chan OracleVerdict)

	var wg sync.WaitGroup
	for i := 0; i < triageWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range in {
				v := triageOne(ctx, client, o)
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

	m := make(map[common.Address]OracleVerdict)
	for v := range out {
		m[v.Oracle] = v
	}
	return m
}

func triageOne(
	ctx context.Context,
	client *ethclient.Client,
	oracle common.Address,
) OracleVerdict {

	v := OracleVerdict{Oracle: oracle}
	code, err := client.CodeAt(ctx, oracle, nil)
	if err != nil || len(code) == 0 {
		return v
	}

	has := func(sel []byte) bool { return containsPUSH4(code, sel) }

	if has(SelGetReserves) {
		v.HasSpotRead = true
		v.Selectors = append(v.Selectors, "getReserves()")
	}
	if has(SelSlot0) {
		v.HasSpotRead = true
		v.Selectors = append(v.Selectors, "slot0()")
	}
	if has(SelBalanceOf) && has(SelTotalSupply) {
		v.HasSpotRead = true
		v.Selectors = append(v.Selectors, "balanceOf()+totalSupply()")
	}
	if has(SelLatestRound) {
		v.HasRobustFeed = true
	}
	if has(SelObserve) {
		v.HasRobustFeed = true
	}

	if v.HasRobustFeed && !v.HasSpotRead {
		v.Whitelisted = true
	}

	v.Shortlisted = v.HasSpotRead && !v.HasRobustFeed && !v.Whitelisted
	return v
}

// containsPUSH4 reports whether the exact PUSH4 <selector> sequence
// appears in the bytecode.
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
