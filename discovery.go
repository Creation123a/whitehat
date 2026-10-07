package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ---------- Constants ----------

// getReservesList() selector on Aave V3 Pool.
var selGetReservesList = []byte{0xd1, 0x94, 0x6d, 0xbc}

// Transfer(address,address,uint256) event topic.
var transferTopic = common.HexToHash(
	"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
)

// CreateMarket(Id,MarketParams) event topic from Morpho Blue.
// keccak256("CreateMarket(bytes32,(address,address,address,address,uint256))")
//
// VERIFY against the deployed Morpho Blue on Base before shipping.
// A wrong topic yields zero logs and a silently empty Morpho path.
var morphoCreateMarketTopic = common.HexToHash(
	"0xac4b2400f169220b0c0afdde7a0b32e775ba727ea1cb30b35f935cdaab8683ac",
)

const discoverWorkers = 16

// ---------- Public entry point ----------

// Discover enumerates candidate vault addresses from Aave V3 and Morpho
// Blue on the chain the client points at, filters EOAs, and returns the
// survivors tagged with their discovery provenance.
func Discover(ctx context.Context, client *ethclient.Client) ([]Candidate, error) {
	head, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}

	d := &discovery{
		client:    client,
		head:      head,
		blocklist: defaultBlocklist(),
		seen:      make(map[common.Address]Candidate),
	}

	// Aave path.
	aaveTokens, err := d.aaveUnderlyings(ctx)
	if err != nil {
		log.Printf("discovery: aave enumeration failed: %v", err)
	}
	if err := d.scanTransfers(ctx, aaveTokens, "aave", AaveV3PoolAddress); err != nil {
		log.Printf("discovery: aave transfer scan failed: %v", err)
	}

	// Morpho path.
	morphoTokens, err := d.morphoUnderlyings(ctx)
	if err != nil {
		log.Printf("discovery: morpho enumeration failed: %v", err)
	}
	if err := d.scanTransfers(ctx, morphoTokens, "morpho", MorphoBlueAddress); err != nil {
		log.Printf("discovery: morpho transfer scan failed: %v", err)
	}

	return d.filterAndEmit(ctx), nil
}

// ---------- State ----------

type discovery struct {
	client *ethclient.Client
	head   uint64

	blocklist map[common.Address]struct{}
	seen      map[common.Address]Candidate
}

func defaultBlocklist() map[common.Address]struct{} {
	return map[common.Address]struct{}{
		MorphoBlueAddress: {},
		AaveV3PoolAddress: {},
		// Add known Base routers here as config is confirmed:
		//  - Uniswap Universal Router
		//  - Aerodrome Router
		//  - BaseSwap Router
	}
}

// ---------- Aave enumeration ----------

func (d *discovery) aaveUnderlyings(ctx context.Context) ([]common.Address, error) {
	raw, err := d.client.CallContract(ctx,
		callMsgData(AaveV3PoolAddress, selGetReservesList), nil)
	if err != nil {
		return nil, fmt.Errorf("getReservesList: %w", err)
	}
	return decodeAddressArray(raw)
}

// ---------- Morpho enumeration ----------

func (d *discovery) morphoUnderlyings(ctx context.Context) ([]common.Address, error) {
	from := uint64(0)
	if d.head > BlockWindowSize {
		from = d.head - BlockWindowSize
	}

	q := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(d.head),
		Addresses: []common.Address{MorphoBlueAddress},
		Topics:    [][]common.Hash{{morphoCreateMarketTopic}},
	}
	logs, err := d.client.FilterLogs(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("CreateMarket filter: %w", err)
	}

	tokens := make(map[common.Address]struct{})
	for _, lg := range logs {
		loan, collateral, err := decodeCreateMarket(lg)
		if err != nil {
			continue
		}
		if loan != (common.Address{}) {
			tokens[loan] = struct{}{}
		}
		if collateral != (common.Address{}) {
			tokens[collateral] = struct{}{}
		}
	}

	out := make([]common.Address, 0, len(tokens))
	for t := range tokens {
		out = append(out, t)
	}
	return out, nil
}

// decodeCreateMarket extracts (loanToken, collateralToken) from a
// CreateMarket log. Non-indexed data is MarketParams:
//
//	[  0: 32] loanToken
//	[ 32: 64] collateralToken
//	[ 64: 96] oracle
//	[ 96:128] irm
//	[128:160] lltv
func decodeCreateMarket(lg types.Log) (loan, collateral common.Address, err error) {
	if len(lg.Data) < 32*5 {
		return common.Address{}, common.Address{}, fmt.Errorf("short data: %d", len(lg.Data))
	}
	loan = common.BytesToAddress(lg.Data[12:32])
	collateral = common.BytesToAddress(lg.Data[32+12 : 64])
	return loan, collateral, nil
}

// ---------- Transfer scan ----------

// scanTransfers queries Transfer logs for the given tokens over the
// discovery window, extracts unique `to` addresses, and records them
// tagged with (protocol, pool). First-seen wins when an address is
// observed under multiple sources.
func (d *discovery) scanTransfers(
	ctx context.Context,
	tokens []common.Address,
	protocol string,
	pool common.Address,
) error {
	if len(tokens) == 0 {
		return nil
	}

	from := uint64(0)
	if d.head > BlockWindowSize {
		from = d.head - BlockWindowSize
	}

	q := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(d.head),
		Addresses: tokens,
		Topics:    [][]common.Hash{{transferTopic}},
	}
	logs, err := d.client.FilterLogs(ctx, q)
	if err != nil {
		return fmt.Errorf("Transfer filter: %w", err)
	}

	for _, lg := range logs {
		if len(lg.Topics) < 3 {
			continue
		}
		to := common.BytesToAddress(lg.Topics[2].Bytes()[12:])
		if to == (common.Address{}) {
			continue
		}
		if _, blocked := d.blocklist[to]; blocked {
			continue
		}
		if _, isToken := d.blocklist[lg.Address]; isToken {
			continue
		}
		if _, exists := d.seen[to]; !exists {
			d.seen[to] = Candidate{
				Address:  to,
				Protocol: protocol,
				Pool:     pool,
			}
		}
	}
	return nil
}

// ---------- EOA filter + emit ----------

func (d *discovery) filterAndEmit(ctx context.Context) []Candidate {
	in := make(chan Candidate)
	out := make(chan Candidate)

	var wg sync.WaitGroup
	for i := 0; i < discoverWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range in {
				code, err := d.client.CodeAt(ctx, c.Address, nil)
				if err != nil || len(code) == 0 {
					continue
				}
				select {
				case out <- c:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, c := range d.seen {
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

	var result []Candidate
	for c := range out {
		result = append(result, c)
	}
	return result
}

// ---------- ABI helpers ----------

// decodeAddressArray decodes an ABI-encoded address[] return value.
func decodeAddressArray(raw []byte) ([]common.Address, error) {
	if len(raw) < 64 {
		return nil, fmt.Errorf("short address[] response: %d", len(raw))
	}
	off := new(big.Int).SetBytes(raw[:32]).Uint64()
	if uint64(len(raw)) < off+32 {
		return nil, fmt.Errorf("bad offset %d (len %d)", off, len(raw))
	}
	n := new(big.Int).SetBytes(raw[off : off+32]).Uint64()
	need := off + 32 + n*32
	if uint64(len(raw)) < need {
		return nil, fmt.Errorf("array truncated: need %d, have %d", need, len(raw))
	}
	out := make([]common.Address, 0, n)
	for i := uint64(0); i < n; i++ {
		base := off + 32 + i*32
		out = append(out, common.BytesToAddress(raw[base+12:base+32]))
	}
	return out, nil
}
