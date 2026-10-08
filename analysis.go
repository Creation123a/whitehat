package main

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// CollateralVerdict is the static analysis result for one collateral asset.
type CollateralVerdict struct {
	Collateral    common.Address
	HasSpotRead   bool
	HasRobustFeed bool
	Selectors     []string
	Whitelisted   bool
	Shortlisted   bool
}

const triageWorkers = 1

// TriageCollateral scans each market's collateral asset bytecode, keeps
// only markets whose collateral reads spot AMM state and has no robust
// Chainlink/TWAP feed in its valuation path.
func TriageCollateral(
	ctx context.Context,
	client *ethclient.Client,
	markets []MorphoMarket,
) []MorphoMarket {

	verdicts := scanUniqueCollaterals(ctx, client, UniqueCollaterals(markets))

	var out []MorphoMarket
	for _, m := range markets {
		v, ok := verdicts[m.CollateralAsset.Address]
		if !ok || !v.Shortlisted {
			continue
		}
		m.CollateralSelectors = v.Selectors
		out = append(out, m)
	}
	return out
}

func scanUniqueCollaterals(
	ctx context.Context,
	client *ethclient.Client,
	collaterals []common.Address,
) map[common.Address]CollateralVerdict {

	in := make(chan common.Address)
	out := make(chan CollateralVerdict)

	var wg sync.WaitGroup
	for i := 0; i < triageWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range in {
				v := triageOneCollateral(ctx, client, c)
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
		for _, c := range collaterals {
			select {
			case in <- c:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	m := make(map[common.Address]CollateralVerdict)
	for v := range out {
		m[v.Collateral] = v
	}
	return m
}

// triageOneCollateral scans the collateral asset's runtime bytecode for
// spot AMM selectors. If it finds getReserves() or slot0(), or
// balanceOf()+totalSupply(), the collateral computes its own value from
// spot AMM state — that is the vulnerability we hunt.
//
// If it finds latestRoundData() or observe(), the collateral uses a
// robust external feed and is discarded.
func triageOneCollateral(
	ctx context.Context,
	client *ethclient.Client,
	collateral common.Address,
) CollateralVerdict {

	v := CollateralVerdict{Collateral: collateral}
	code, err := client.CodeAt(ctx, collateral, nil)
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
