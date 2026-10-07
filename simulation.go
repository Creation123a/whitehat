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

// ---------- Selectors (local to this file) ----------

var (
	selGetReserves = []byte{0x09, 0x02, 0xf1, 0xac} // getReserves()
	selSlot0       = []byte{0x38, 0x50, 0xc7, 0xbd} // slot0()
)

// ---------- AMM kinds ----------

const (
	ammUniswapV2        = "uniswap-v2"
	ammUniswapV3        = "uniswap-v3"
	ammAerodromeV2      = "aerodrome-v2"
	ammAerodromeSlipstr = "aerodrome-slipstream"
)

// ---------- Storage slots ----------

// Uniswap V2 / V2-fork packed reserves.
// Layout: [reserve0:112][reserve1:112][blockTimestampLast:32] at slot 8.
var slotUniswapV2Reserves = common.BigToHash(big.NewInt(8))

// Uniswap V3 slot0 at slot 0.
// Layout: [sqrtPriceX96:160][tick:24][observationIndex:16]
//         [observationCardinality:16][observationCardinalityNext:16]
//         [feeProtocol:8][unlocked:8]
var slotUniswapV3Slot0 = common.BigToHash(big.NewInt(0))

// Aerodrome V2 (Solidly fork) packed reserves.
//
// Aerodrome Pool.sol is not a Uniswap V2 clone at the storage level:
// it uses uint256 reserve0 and uint256 reserve1 in separate slots,
// plus stable/decimals/fees state ahead of them. The actual slot is
// determined by the Solidity layout of:
//
//	contract Pool {
//	    address public token0;   // slot 0
//	    address public token1;   // slot 1
//	    bool    public stable;   // slot 2 (packed)
//	    ...
//	    uint256 public reserve0; // slot N
//	    uint256 public reserve1; // slot N+1
//	}
//
// VERIFY by reading Pool.sol storage layout from the deployed
// implementation on BaseScan before trusting the mutation.
var slotAerodromeV2Reserve0 = common.BigToHash(big.NewInt(12)) // TODO: verify
var slotAerodromeV2Reserve1 = common.BigToHash(big.NewInt(13)) // TODO: verify

// Aerodrome Slipstream slot0.
//
// Slipstream CLPool.sol is adapted from Uniswap V3 but drops
// feeProtocol from slot0, so the packed layout is:
//
//	[sqrtPriceX96:160][tick:24][observationIndex:16]
//	[observationCardinality:16][observationCardinalityNext:16][unlocked:8]
//
// The slot itself is still slot 0 (slot0 is the first declared state var).
var slotAerodromeSlipstreamSlot0 = common.BigToHash(big.NewInt(0))

// ---------- Shift factors ----------

var (
	shiftV2Num = big.NewInt(110) // +10%
	shiftV2Den = big.NewInt(100)

	shiftV3Num = big.NewInt(95) // -5% sqrtPriceX96 (≈ -10% spot)
	shiftV3Den = big.NewInt(100)
)

var confirmThresholdBps = big.NewInt(50) // 0.50%

// ---------- Bit masks ----------

var (
	mask112 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	mask160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
)

// ---------- Entry point ----------

func Simulate(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	suspected []Finding,
) []Finding {

	confirmed := make([]Finding, 0, len(suspected))
	for i := range suspected {
		f := suspected[i]
		ok, ev := simulateOne(ctx, client, rpcClient, f)
		if !ok {
			continue
		}
		f.Verified = true
		f.Evidence = ev
		confirmed = append(confirmed, f)
	}
	return confirmed
}

// ---------- Per-finding simulation ----------

func simulateOne(
	ctx context.Context,
	client *ethclient.Client,
	rpcClient *rpc.Client,
	f Finding,
) (bool, string) {

	pool, kind, err := locateAMMPool(ctx, client, f.Vault)
	if err != nil {
		log.Printf("simulate %s: locate AMM pool: %v", f.Vault.Hex(), err)
		return false, ""
	}

	base, err := callBig(ctx, client, f.Vault, selTotalAssets)
	if err != nil || base.Sign() == 0 {
		return false, ""
	}

	snap, err := takeSnapshot(ctx, rpcClient)
	if err != nil {
		log.Printf("simulate %s: snapshot: %v", f.Vault.Hex(), err)
		return false, ""
	}
	defer func() {
		revertSnapshot(context.Background(), rpcClient, snap)
	}()

	// Dispatch on AMM kind. Each branch returns the mutated slot
	// and value, or an error if the original state is unusable.
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
			return false, ""
		}
		mutated, label, err = shiftV2ReservesPacked(original, mask112, 112)
		if err != nil {
			return false, ""
		}

	case ammUniswapV3:
		slot = slotUniswapV3Slot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return false, ""
		}
		mutated, label, err = shiftV3Slot0(original, mask160, 160)
		if err != nil {
			return false, ""
		}

	case ammAerodromeV2:
		// Aerodrome V2 reserves are uint256 in two separate slots.
		// We mutate reserve0 only; reserve1 stays put.
		slot = slotAerodromeV2Reserve0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return false, ""
		}
		mutated, label, err = shiftAerodromeV2Reserve0(original)
		if err != nil {
			return false, ""
		}

	case ammAerodromeSlipstr:
		slot = slotAerodromeSlipstreamSlot0
		original, err := readSlot(ctx, client, pool, slot)
		if err != nil {
			return false, ""
		}
		mutated, label, err = shiftSlipstreamSlot0(original)
		if err != nil {
			return false, ""
		}

	default:
		return false, ""
	}

	if err := setStorage(ctx, rpcClient, pool, slot, mutated); err != nil {
		log.Printf("simulate %s: setStorageAt: %v", f.Vault.Hex(), err)
		return false, ""
	}

	after, err := callBig(ctx, client, f.Vault, selTotalAssets)
	if err != nil {
		return false, ""
	}

	delta := new(big.Int).Sub(after, base)
	absDelta := new(big.Int).Abs(delta)
	bps := new(big.Int).Mul(absDelta, big.NewInt(10000))
	bps.Div(bps, base)

	if bps.Cmp(confirmThresholdBps) <= 0 {
		return false, ""
	}

	pct := float64(bps.Int64()) / 100.0
	evidence := fmt.Sprintf(
		"totalAssets moved %.2f%% when %s (%s at %s); invariant tracks spot",
		pct, label, kind, pool.Hex())
	return true, evidence
}

// ---------- AMM pool discovery ----------

// locateAMMPool scans the vault's runtime bytecode for PUSH20 constants
// and probes each candidate. Kind detection order matters: we check
// getReserves() first, then slot0(). If a candidate answers getReserves()
// we still need to distinguish Uniswap V2 from Aerodrome V2 — they share
// the same selector. We do that by calling stable() (Aerodrome-only).
func locateAMMPool(
	ctx context.Context,
	client *ethclient.Client,
	vault common.Address,
) (common.Address, string, error) {

	code, err := client.CodeAt(ctx, vault, nil)
	if err != nil {
		return common.Address{}, "", err
	}

	for _, addr := range extractPUSH20Candidates(code) {
		// --- getReserves() path: Uniswap V2 or Aerodrome V2 ---
		if _, err := callBig(ctx, client, addr, selGetReserves); err == nil {
			if _, err := callBig(ctx, client, addr, selStable); err == nil {
				return addr, ammAerodromeV2, nil
			}
			return addr, ammUniswapV2, nil
		}

		// --- slot0() path: Uniswap V3 or Aerodrome Slipstream ---
		if _, err := callBig(ctx, client, addr, selSlot0); err == nil {
			// Distinguish by probe: Slipstream has no feeProtocol()
			// in its ABI. If the call reverts, it's Slipstream.
			if _, err := callBig(ctx, client, addr, selFeeProtocol); err == nil {
				return addr, ammUniswapV3, nil
			}
			return addr, ammAerodromeSlipstr, nil
		}
	}
	return common.Address{}, "", fmt.Errorf("no AMM pool resolved")
}

// selStable and selFeeProtocol are used only for kind detection.
var (
	selStable      = []byte{0x22, 0xbe, 0x12, 0xe4} // stable()
	selFeeProtocol = []byte{0x82, 0x06, 0xbc, 0x24} // feeProtocol()
)

func extractPUSH20Candidates(code []byte) []common.Address {
	seen := make(map[common.Address]struct{})
	var out []common.Address
	for i := 0; i+21 <= len(code); i++ {
		if code[i] != 0x73 { // PUSH20
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

// shiftV2ReservesPacked handles Uniswap V2's packed 112/112/32 layout.
// width parameter is 112 for Uniswap V2.
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

// shiftAerodromeV2Reserve0 handles Aerodrome V2's uint256 reserve0.
// No masking needed — the whole slot is the reserve.
func shiftAerodromeV2Reserve0(old common.Hash) (common.Hash, string, error) {
	v := new(big.Int).SetBytes(old.Bytes())
	if v.Sign() == 0 {
		return common.Hash{}, "", fmt.Errorf("zero reserve0")
	}
	newReserve0 := new(big.Int).Mul(v, shiftV2Num)
	newReserve0.Div(newReserve0, shiftV2Den)

	pct := shiftV2Num.Int64() - 100
	return common.BigToHash(newReserve0),
		fmt.Sprintf("+%d%% aerodrome reserve0", pct), nil
}

// shiftV3Slot0 handles Uniswap V3's packed slot0.
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
		fmt.Sprintf("sqrtPriceX96 -%d%% (~%d%% spot)", pct, pct*2), nil
}

// shiftSlipstreamSlot0 handles Aerodrome Slipstream's slot0, which
// shares the same [sqrtPriceX96:160] low bits as Uniswap V3. The
// difference is only in the bits above 160, which we preserve wholesale.
// So the mutation is byte-identical to shiftV3Slot0 — the distinct
// function exists to make the AMM kind explicit in the code path.
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
