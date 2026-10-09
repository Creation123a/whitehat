package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	ammUniswapV2        = "uniswap-v2"
	ammUniswapV3        = "uniswap-v3"
	ammAerodromeV2      = "aerodrome-v2"
	ammAerodromeSlipstr = "aerodrome-slipstream"
)

var (
	slotUniswapV2Reserves        = common.BigToHash(big.NewInt(int64(SlotUniswapV2Reserves)))
	slotUniswapV3Slot0           = common.BigToHash(big.NewInt(int64(SlotUniswapV3Slot0)))
	slotAerodromeV2Reserve0      = common.BigToHash(big.NewInt(int64(SlotAerodromeV2Reserve0)))
	slotAerodromeSlipstreamSlot0 = common.BigToHash(big.NewInt(int64(SlotAerodromeSlipstreamSlot0)))
)

var (
	shiftV2Num = big.NewInt(110)
	shiftV2Den = big.NewInt(100)
	shiftV3Num = big.NewInt(95)
	shiftV3Den = big.NewInt(100)
	mask112 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	mask160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
)

type ConfirmedMarket struct {
	Market      MorphoMarket
	Protocols   []Protocol
	Pool        common.Address
	PoolKind    string
	PriceBefore *big.Int
	PriceAfter  *big.Int
	DeltaPct    float64
	Evidence    string
}

type SuspectedMarket struct {
	Market    MorphoMarket
	Protocols []Protocol
	Reason    string
}

func Simulate(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	in []MarketWithProtocols,
) ([]ConfirmedMarket, []SuspectedMarket) {

	var confirmed []ConfirmedMarket
	var suspected []SuspectedMarket

	for _, mp := range in {
		cm, reason, ok := simulateOne(ctx, client, rpcClient, mp)
		if ok {
			confirmed = append(confirmed, cm)
			continue
		}
		suspected = append(suspected, SuspectedMarket{
			Market:    mp.Market,
			Protocols: mp.Protocols,
			Reason:    reason,
		})
	}
	return confirmed, suspected
}

func simulateOne(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	mp MarketWithProtocols,
) (ConfirmedMarket, string, bool) {

	m := mp.Market

	pools := m.TracedPools
	if len(pools) == 0 {
		pool, _, err := locateAMMPoolDual(ctx, client, m.Oracle, m.CollateralAsset.Address)
		if err != nil {
			return ConfirmedMarket{}, "pool_not_resolved: " + err.Error(), false
		}
		pools = []common.Address{pool}
	}

	base, err := callBig(ctx, client, m.Oracle, SelPrice)
	if err != nil || base.Sign() == 0 {
		return ConfirmedMarket{}, "oracle_call_failed", false
	}

	threshold := minDeltaForPair(m.LoanAsset, m.CollateralAsset)
	lastReason := "no_pool_confirmed"
	for _, pool := range pools {
		kind := detectAMMKind(ctx, client, pool)
		if kind == "" {
			lastReason = "traced_pool_not_amm"
			continue
		}
		cm, reason, ok := tryPool(ctx, client, rpcClient, m, mp.Protocols,
			pool, kind, base, threshold)
		if ok {
			return cm, "", true
		}
		lastReason = reason
	}
	return ConfirmedMarket{}, lastReason, false
}

func tryPool(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	m MorphoMarket,
	protocols []Protocol,
	pool common.Address,
	kind string,
	base *big.Int,
	threshold float64,
) (ConfirmedMarket, string, bool) {

	snap, err := takeSnapshot(ctx, rpcClient)
	if err != nil {
		return ConfirmedMarket{}, "snapshot_failed: " + err.Error(), false
	}
	defer func() {
		if err := revertSnapshot(context.Background(), rpcClient, snap); err != nil {
			log.Printf("simulate %s: revert failed: %v", m.Oracle.Hex(), err)
		}
	}()

	label, err := mutatePool(ctx, client, rpcClient, pool, kind)
	if err != nil {
		return ConfirmedMarket{}, "mutation_failed: " + err.Error(), false
	}

	after, err := callBig(ctx, client, m.Oracle, SelPrice)
	if err != nil {
		return ConfirmedMarket{}, "oracle_call_after_failed", false
	}

	pct := pctDelta(base, after)
	if pct < threshold {
		return ConfirmedMarket{},
			fmt.Sprintf("delta_below_threshold: %.4f%% < %.2f%%", pct, threshold), false
	}

	evidence := fmt.Sprintf(
		"oracle.price() moved %.2f%% (%s -> %s) when %s shifted (%s pool %s); "+
			"%d protocol(s) supply to this market and are exposed",
		pct, base.String(), after.String(), label, kind, pool.Hex(), len(protocols))

	return ConfirmedMarket{
		Market:      m,
		Protocols:   protocols,
		Pool:        pool,
		PoolKind:    kind,
		PriceBefore: base,
		PriceAfter:  after,
		DeltaPct:    pct,
		Evidence:    evidence,
	}, "", true
}

func pctDelta(base, after *big.Int) float64 {
	if base.Sign() == 0 {
		return 0
	}
	d := new(big.Int).Sub(after, base)
	abs := new(big.Int).Abs(d)
	f := new(big.Float).Quo(new(big.Float).SetInt(abs), new(big.Float).SetInt(base))
	f.Mul(f, big.NewFloat(100))
	v, _ := f.Float64()
	return v
}

func mutatePool(ctx context.Context, client *ethclient.Client, rpcClient *rpc.Client, pool common.Address, kind string) (string, error) {
	switch kind {
	case ammUniswapV2:
		slot := slotUniswapV2Reserves
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return "", err
		}
		mutated, label, err := shiftV2ReservesPacked(original, mask112, 112)
		if err != nil {
			return "", err
		}
		return label, setStorage(ctx, rpcClient, pool, slot, mutated)
	case ammUniswapV3:
		slot := slotUniswapV3Slot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return "", err
		}
		mutated, label, err := shiftV3Slot0(original, mask160, 160)
		if err != nil {
			return "", err
		}
		return label, setStorage(ctx, rpcClient, pool, slot, mutated)
	case ammAerodromeV2:
		slot := slotAerodromeV2Reserve0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return "", err
		}
		mutated, label, err := shiftAerodromeV2Reserve0(original)
		if err != nil {
			return "", err
		}
		return label, setStorage(ctx, rpcClient, pool, slot, mutated)
	case ammAerodromeSlipstr:
		slot := slotAerodromeSlipstreamSlot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return "", err
		}
		mutated, label, err := shiftSlipstreamSlot0(original)
		if err != nil {
			return "", err
		}
		return label, setStorage(ctx, rpcClient, pool, slot, mutated)
	}
	return "", fmt.Errorf("unknown_amm_kind")
}

func locateAMMPoolDual(ctx context.Context, client *ethclient.Client, oracle, collateral common.Address) (common.Address, string, error) {
	if collateral != (common.Address{}) {
		if _, err := callBig(ctx, client, collateral, SelGetReserves); err == nil {
			if _, err := callBig(ctx, client, collateral, SelStable); err == nil {
				return collateral, ammAerodromeV2, nil
			}
			return collateral, ammUniswapV2, nil
		}
		if _, err := callBig(ctx, client, collateral, SelSlot0); err == nil {
			if _, err := callBig(ctx, client, collateral, SelFeeProtocol); err == nil {
				return collateral, ammUniswapV3, nil
			}
			return collateral, ammAerodromeSlipstr, nil
		}
	}
	for _, target := range []common.Address{oracle, collateral} {
		if target == (common.Address{}) {
			continue
		}
		code, err := client.CodeAt(ctx, target, nil)
		if err != nil || len(code) == 0 {
			continue
		}
		for _, addr := range extractPUSH20Candidates(code) {
			if _, err := callBig(ctx, client, addr, SelGetReserves); err == nil {
				if _, err := callBig(ctx, client, addr, SelStable); err == nil {
					return addr, ammAerodromeV2, nil
				}
				return addr, ammUniswapV2, nil
			}
			if _, err := callBig(ctx, client, addr, SelSlot0); err == nil {
				if _, err := callBig(ctx, client, addr, SelFeeProtocol); err == nil {
					return addr, ammUniswapV3, nil
				}
				return addr, ammAerodromeSlipstr, nil
			}
		}
	}
	return common.Address{}, "", fmt.Errorf("no AMM pool resolved")
}

func extractPUSH20Candidates(code []byte) []common.Address {
	seen := make(map[common.Address]struct{})
	var out []common.Address
	for i := 0; i+21 <= len(code); i++ {
		if code[i] != 0x73 {
			continue
		}
		addr := common.BytesToAddress(code[i+1 : i+21])
		if addr == (common.Address{}) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func shiftV2ReservesPacked(old common.Hash, mask *big.Int, width uint) (common.Hash, string, error) {
	v := new(big.Int).SetBytes(old.Bytes())
	r0 := new(big.Int).And(v, mask)
	if r0.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero reserve0")
	}
	nr0 := new(big.Int).Mul(r0, shiftV2Num)
	nr0.Div(nr0, shiftV2Den)
	if nr0.BitLen() > int(width) {
		return common.Hash{}, "", fmt.Errorf("reserve0 overflow")
	}
	cleared := new(big.Int).And(v, new(big.Int).Not(mask))
	return common.BigToHash(new(big.Int).Or(cleared, nr0)),
		fmt.Sprintf("+%d%% reserve0", shiftV2Num.Int64()-100), nil
}

func shiftAerodromeV2Reserve0(old common.Hash) (common.Hash, string, error) {
	v := new(big.Int).SetBytes(old.Bytes())
	if v.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero reserve0")
	}
	nr0 := new(big.Int).Mul(v, shiftV2Num)
	nr0.Div(nr0, shiftV2Den)
	return common.BigToHash(nr0),
		fmt.Sprintf("+%d%% reserve0", shiftV2Num.Int64()-100), nil
}

func shiftV3Slot0(old common.Hash, mask *big.Int, width uint) (common.Hash, string, error) {
	v := new(big.Int).SetBytes(old.Bytes())
	sp := new(big.Int).And(v, mask)
	if sp.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero sqrtPriceX96")
	}
	ns := new(big.Int).Mul(sp, shiftV3Num)
	ns.Div(ns, shiftV3Den)
	cleared := new(big.Int).And(v, new(big.Int).Not(mask))
	return common.BigToHash(new(big.Int).Or(cleared, ns)),
		fmt.Sprintf("sqrtPriceX96 -%d%%", 100-shiftV3Num.Int64()), nil
}

func shiftSlipstreamSlot0(old common.Hash) (common.Hash, string, error) {
	return shiftV3Slot0(old, mask160, 160)
}

func readSlot(ctx context.Context, client *ethclient.Client, addr common.Address, slot common.Hash) (common.Hash, error) {
	raw, err := client.StorageAt(ctx, addr, slot, nil)
	if err != nil {
		return common.Hash{}, err
	}
	if len(raw) != 32 {
		return common.Hash{}, fmt.Errorf("bad slot response: %d bytes", len(raw))
	}
	return common.BytesToHash(raw), nil
}

func setStorage(ctx context.Context, c *rpc.Client, addr common.Address, slot, value common.Hash) error {
	var res interface{}
	if err := c.CallContext(ctx, &res, "anvil_setStorageAt", addr.Hex(), slot.Hex(), value.Hex()); err == nil {
		return nil
	}
	return c.CallContext(ctx, &res, "hardhat_setStorageAt", addr.Hex(), slot.Hex(), value.Hex())
}

func takeSnapshot(ctx context.Context, c *rpc.Client) (string, error) {
	var id string
	if err := c.CallContext(ctx, &id, "anvil_snapshot"); err == nil {
		return id, nil
	}
	return id, c.CallContext(ctx, &id, "evm_snapshot")
}

func revertSnapshot(ctx context.Context, c *rpc.Client, id string) error {
	var ok bool
	if err := c.CallContext(ctx, &ok, "anvil_revert", id); err == nil {
		return nil
	}
	return c.CallContext(ctx, &ok, "evm_revert", id)
}

func detectAMMKind(ctx context.Context, client *ethclient.Client, pool common.Address) string {
	if _, err := callBig(ctx, client, pool, SelGetReserves); err == nil {
		if _, err := callBig(ctx, client, pool, SelStable); err == nil {
			return ammAerodromeV2
		}
		return ammUniswapV2
	}
	if _, err := callBig(ctx, client, pool, SelSlot0); err == nil {
		if _, err := callBig(ctx, client, pool, SelFeeProtocol); err == nil {
			return ammUniswapV3
		}
		return ammAerodromeSlipstr
	}
	return ""
}
