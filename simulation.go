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

// ---------- AMM kinds ----------

const (
	ammUniswapV2        = "uniswap-v2"
	ammUniswapV3        = "uniswap-v3"
	ammAerodromeV2      = "aerodrome-v2"
	ammAerodromeSlipstr = "aerodrome-slipstream"
)

// ---------- Storage slots (sourced from config.go) ----------

var (
	slotUniswapV2Reserves        = common.BigToHash(big.NewInt(int64(SlotUniswapV2Reserves)))
	slotUniswapV3Slot0           = common.BigToHash(big.NewInt(int64(SlotUniswapV3Slot0)))
	slotAerodromeV2Reserve0      = common.BigToHash(big.NewInt(int64(SlotAerodromeV2Reserve0)))
	slotAerodromeSlipstreamSlot0 = common.BigToHash(big.NewInt(int64(SlotAerodromeSlipstreamSlot0)))
)

// ---------- Shift factors ----------

var (
	shiftV2Num = big.NewInt(110) // +10%
	shiftV2Den = big.NewInt(100)

	shiftV3Num = big.NewInt(95) // -5% sqrtPriceX96 (≈ -10% spot)
	shiftV3Den = big.NewInt(100)
)

// ---------- Bit masks ----------

var (
	mask112 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	mask160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
)

// ---------- ConfirmedMarket ----------

// ConfirmedMarket carries the fork-verified evidence for one market.
type ConfirmedMarket struct {
	Market      MorphoMarket
	Pool        common.Address
	PoolKind    string
	PriceBefore *big.Int
	PriceAfter  *big.Int
	DeltaPct    float64
	Evidence    string
}

// Simulate runs the fork test on each shortlisted market. Returns only
// SuspectedMarket is a shortlisted market that passed bytecode triage
// but did not confirm in the fork simulation.
type SuspectedMarket struct {
	Market MorphoMarket
	Reason string // why confirmation failed
}

// Simulate runs the fork test on each shortlisted market. Returns two
// slices: markets where oracle.price() moved more than MinDeltaPct,
// and markets that failed confirmation (with the reason). The suspected
// list is not a failure — it is the manual-review queue.
//
// Serial by design: Anvil state is global, and parallel mutations of
// shared pools would corrupt each other's baselines.
func Simulate(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	shortlist []MorphoMarket,
) ([]ConfirmedMarket, []SuspectedMarket) {

	var confirmed []ConfirmedMarket
	var suspected []SuspectedMarket

	for i := range shortlist {
		cm, reason, ok := simulateOne(ctx, client, rpcClient, shortlist[i])
		if ok {
			confirmed = append(confirmed, cm)
			continue
		}
		suspected = append(suspected, SuspectedMarket{
			Market: shortlist[i],
			Reason: reason,
		})
	}
	return confirmed, suspected
}
// simulateOne returns (confirmed, reason, ok). ok=true means confirmed.
// ok=false means suspected, and reason explains why.
func simulateOne(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	m MorphoMarket,
) (ConfirmedMarket, string, bool) {

	pool, kind, err := locateAMMPool(ctx, client, m.Oracle)
	if err != nil {
		return ConfirmedMarket{}, "pool_not_resolved: " + err.Error(), false
	}

	base, err := callBig(ctx, client, m.Oracle, SelPrice)
	if err != nil || base.Sign() == 0 {
		return ConfirmedMarket{}, "oracle_call_failed", false
	}

	snap, err := takeSnapshot(ctx, rpcClient)
	if err != nil {
		return ConfirmedMarket{}, "snapshot_failed: " + err.Error(), false
	}
	defer func() {
		if err := revertSnapshot(context.Background(), rpcClient, snap); err != nil {
			log.Printf("simulate %s: revert failed: %v", m.Oracle.Hex(), err)
		}
	}()

	var (
		slot    common.Hash
		mutated common.Hash
		label   string
	)

	switch kind {
	case ammUniswapV2:
		slot = slotUniswapV2Reserves
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return ConfirmedMarket{}, "read_slot_failed", false
		}
		mutated, label, err = shiftV2ReservesPacked(original, mask112, 112)
		if err != nil {
			return ConfirmedMarket{}, "mutation_failed: " + err.Error(), false
		}

	case ammUniswapV3:
		slot = slotUniswapV3Slot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return ConfirmedMarket{}, "read_slot_failed", false
		}
		mutated, label, err = shiftV3Slot0(original, mask160, 160)
		if err != nil {
			return ConfirmedMarket{}, "mutation_failed: " + err.Error(), false
		}

	case ammAerodromeV2:
		slot = slotAerodromeV2Reserve0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return ConfirmedMarket{}, "read_slot_failed", false
		}
		mutated, label, err = shiftAerodromeV2Reserve0(original)
		if err != nil {
			return ConfirmedMarket{}, "mutation_failed: " + err.Error(), false
		}

	case ammAerodromeSlipstr:
		slot = slotAerodromeSlipstreamSlot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return ConfirmedMarket{}, "read_slot_failed", false
		}
		mutated, label, err = shiftSlipstreamSlot0(original)
		if err != nil {
			return ConfirmedMarket{}, "mutation_failed: " + err.Error(), false
		}

	default:
		return ConfirmedMarket{}, "unknown_amm_kind", false
	}

	if err := setStorage(ctx, rpcClient, pool, slot, mutated); err != nil {
		return ConfirmedMarket{}, "storage_write_failed: " + err.Error(), false
	}

	after, err := callBig(ctx, client, m.Oracle, SelPrice)
	if err != nil {
		return ConfirmedMarket{}, "oracle_call_after_failed", false
	}

	delta := new(big.Int).Sub(after, base)
	absDelta := new(big.Int).Abs(delta)
	pctF := new(big.Float).Quo(
		new(big.Float).SetInt(absDelta),
		new(big.Float).SetInt(base),
	)
	pctF.Mul(pctF, big.NewFloat(100))
	pct, _ := pctF.Float64()

	if pct < MinDeltaPct {
		return ConfirmedMarket{},
			fmt.Sprintf("delta_below_threshold: %.4f%% < %.2f%%", pct, MinDeltaPct),
			false
	}

	evidence := fmt.Sprintf(
		"oracle.price() moved %.2f%% (%s → %s) when %s shifted (%s pool %s)",
		pct, base.String(), after.String(), label, kind, pool.Hex())

	return ConfirmedMarket{
		Market:      m,
		Pool:        pool,
		PoolKind:    kind,
		PriceBefore: base,
		PriceAfter:  after,
		DeltaPct:    pct,
		Evidence:    evidence,
	}, "", true
}
	
func locateAMMPool(
	ctx context.Context,
	client *ethclient.Client,
	oracle common.Address,
) (common.Address, string, error) {

	code, err := client.CodeAt(ctx, oracle, nil)
	if err != nil {
		return common.Address{}, "", err
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

// ---------- Storage mutations ----------

func shiftV2ReservesPacked(
	old common.Hash,
	mask *big.Int,
	width uint,
) (common.Hash, string, error) {

	v := new(big.Int).SetBytes(old.Bytes())
	reserve0 := new(big.Int).And(v, mask)
	if reserve0.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero reserve0")
	}
	newReserve0 := new(big.Int).Mul(reserve0, shiftV2Num)
	newReserve0.Div(newReserve0, shiftV2Den)
	if newReserve0.BitLen() > int(width) {
		return common.Hash{}, "", fmt.Errorf("reserve0 overflow")
	}
	cleared := new(big.Int).And(v, new(big.Int).Not(mask))
	result := new(big.Int).Or(cleared, newReserve0)
	pct := shiftV2Num.Int64() - 100
	return common.BigToHash(result), fmt.Sprintf("+%d%% reserve0", pct), nil
}

func shiftAerodromeV2Reserve0(old common.Hash) (common.Hash, string, error) {
	v := new(big.Int).SetBytes(old.Bytes())
	if v.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero reserve0")
	}
	newReserve0 := new(big.Int).Mul(v, shiftV2Num)
	newReserve0.Div(newReserve0, shiftV2Den)
	pct := shiftV2Num.Int64() - 100
	return common.BigToHash(newReserve0),
		fmt.Sprintf("+%d%% reserve0", pct), nil
}

func shiftV3Slot0(
	old common.Hash,
	mask *big.Int,
	width uint,
) (common.Hash, string, error) {

	v := new(big.Int).SetBytes(old.Bytes())
	sqrtPrice := new(big.Int).And(v, mask)
	if sqrtPrice.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero sqrtPriceX96")
	}
	newSqrt := new(big.Int).Mul(sqrtPrice, shiftV3Num)
	newSqrt.Div(newSqrt, shiftV3Den)
	cleared := new(big.Int).And(v, new(big.Int).Not(mask))
	result := new(big.Int).Or(cleared, newSqrt)
	pct := 100 - shiftV3Num.Int64()
	return common.BigToHash(result),
		fmt.Sprintf("sqrtPriceX96 -%d%%", pct), nil
}

func shiftSlipstreamSlot0(old common.Hash) (common.Hash, string, error) {
	return shiftV3Slot0(old, mask160, 160)
}

// ---------- RPC helpers ----------

func readSlot(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
	slot common.Hash,
) (common.Hash, error) {

	raw, err := client.StorageAt(ctx, addr, slot, nil)
	if err != nil {
		return common.Hash{}, err
	}
	if len(raw) != 32 {
		return common.Hash{}, fmt.Errorf("bad slot response: %d bytes", len(raw))
	}
	return common.BytesToHash(raw), nil
}

func setStorage(
	ctx context.Context,
	c *rpc.Client,
	addr common.Address,
	slot, value common.Hash,
) error {

	var res interface{}
	err := c.CallContext(ctx, &res, "anvil_setStorageAt",
		addr.Hex(), slot.Hex(), value.Hex())
	if err == nil {
		return nil
	}
	return c.CallContext(ctx, &res, "hardhat_setStorageAt",
		addr.Hex(), slot.Hex(), value.Hex())
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
