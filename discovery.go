package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ---------- Event topics ----------
//
// Aave V3 user events:
//   cast keccak "Supply(address,address,address,uint256,uint16)"
//   cast keccak "Borrow(address,address,address,uint256,uint8,uint256,uint16)"
//
// Morpho Blue user events:
//   cast keccak "Supply(bytes32,address,address,uint256,uint256)"
//   cast keccak "Borrow(bytes32,address,address,address,uint256,uint256)"
//   cast keccak "SupplyCollateral(bytes32,address,address,uint256)"
//
// VERIFY all five hashes with cast before running. A wrong topic
// silently yields zero candidates for that event.

var (
	aaveSupplyTopic = common.HexToHash(
		"0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61")
	aaveBorrowTopic = common.HexToHash(
		"0xb3d084820fb1a9decffb176436bd02558d15f68fc2cd2ed89e3ac68d0e5d0f0e")

	morphoSupplyTopic = common.HexToHash(
		"0xedf8870433c83823eb071d3df1caa8d008f12f6440918c20d75a3602cda30fe0")
	morphoBorrowTopic = common.HexToHash(
		"0x570954540bed6b1304a87dfe815a5eda4a648f7097a16240dcd85c9b5fd42a43")
	morphoSupplyCollateralTopic = common.HexToHash(
		"0xa3b9472a1399e17e123f3c2e6586c23e504184d504de59cdaa2b375e880c6184")
)

const discoverWorkers = 1

// eventSpec describes one event topic and the 0-based index of the
// "user" address within its Topics array.
type eventSpec struct {
	topic         common.Hash
	onBehalfTopic int
}

// ---------- Public entry point ----------

// Discover enumerates user addresses of Aave V3 and Morpho Blue over the
// discovery window. The user (onBehalfOf / onBehalf) is the address that
// the protocol acts for — for a vault calling Aave, that is the vault.
// Filters out EOAs so only contracts ("protocols built on Aave/Morpho")
// survive.
func Discover(ctx context.Context, client *ethclient.Client) ([]Candidate, error) {
	head, err := client.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}

	d := &discovery{
		client:    client,
		head:      head,
		blocklist: defaultBlocklist(),
		seen:      make(map[candidateKey]Candidate),
	}

	// Aave users.
	aaveSpecs := []eventSpec{
		{topic: aaveSupplyTopic, onBehalfTopic: 2},
		{topic: aaveBorrowTopic, onBehalfTopic: 2},
	}
	if err := d.scanProtocolUsers(ctx, AaveV3PoolAddress, "aave", aaveSpecs); err != nil {
		log.Printf("discovery: aave user scan failed: %v", err)
	}

	// Morpho users.
	morphoSpecs := []eventSpec{
		{topic: morphoSupplyTopic, onBehalfTopic: 3},
		{topic: morphoBorrowTopic, onBehalfTopic: 2},
		{topic: morphoSupplyCollateralTopic, onBehalfTopic: 3},
	}
	if err := d.scanProtocolUsers(ctx, MorphoBlueAddress, "morpho", morphoSpecs); err != nil {
		log.Printf("discovery: morpho user scan failed: %v", err)
	}

	return d.filterAndEmit(ctx), nil
}

// ---------- State ----------

type candidateKey struct {
	address  common.Address
	protocol string
}

type discovery struct {
	client *ethclient.Client
	head   uint64

	blocklist map[common.Address]struct{}
	seen      map[candidateKey]Candidate
}

func defaultBlocklist() map[common.Address]struct{} {
	return map[common.Address]struct{}{
		MorphoBlueAddress:          {},
		AaveV3PoolAddress:          {},
		AerodromePoolFactory:       {},
		AerodromeRouter:            {},
		AerodromeSlipstreamFactory: {},
	}
}

// ---------- User-event scan ----------

// scanProtocolUsers queries the given user events on the protocol contract
// over the discovery window, extracts the onBehalfOf / onBehalf address
// from each event, and records it tagged with (protocol, pool).
//
// A contract may appear under both "aave" and "morpho" if it uses both.
func (d *discovery) scanProtocolUsers(
	ctx context.Context,
	protocolContract common.Address,
	protocol string,
	specs []eventSpec,
) error {
	from := uint64(0)
	if d.head > BlockWindowSize {
		from = d.head - BlockWindowSize
	}

	for _, spec := range specs {
		q := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(from),
			ToBlock:   new(big.Int).SetUint64(d.head),
			Addresses: []common.Address{protocolContract},
			Topics:    [][]common.Hash{{spec.topic}},
		}
		logs, err := d.filterLogsChunked(ctx, q)
		if err != nil {
			return fmt.Errorf("event %s: %w", spec.topic.Hex(), err)
		}

		for _, lg := range logs {
			if len(lg.Topics) <= spec.onBehalfTopic {
				continue
			}
			user := common.BytesToAddress(lg.Topics[spec.onBehalfTopic].Bytes()[12:])
			if user == (common.Address{}) {
				continue
			}
			if _, blocked := d.blocklist[user]; blocked {
				continue
			}
			key := candidateKey{address: user, protocol: protocol}
			if _, exists := d.seen[key]; !exists {
				d.seen[key] = Candidate{
					Address:  user,
					Protocol: protocol,
					Pool:     protocolContract,
				}
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
		// Deterministic order: by address, then by protocol.
		keys := make([]candidateKey, 0, len(d.seen))
		for k := range d.seen {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if c := bytes.Compare(keys[i].address[:], keys[j].address[:]); c != 0 {
				return c < 0
			}
			return keys[i].protocol < keys[j].protocol
		})
		for _, k := range keys {
			c := d.seen[k]
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

// ---------- Chunked log filter ----------

// filterLogsChunked splits a log query into chunk-sized ranges and merges
// results. Required for RPC providers that cap eth_getLogs ranges
// (Alchemy free tier caps at 10 blocks per call).
func (d *discovery) filterLogsChunked(
	ctx context.Context,
	q ethereum.FilterQuery,
) ([]types.Log, error) {

	from := q.FromBlock.Uint64()
	to := q.ToBlock.Uint64()

	chunk := LogChunkSize
	if chunk == 0 {
		chunk = 10
	}

	var all []types.Log
	for start := from; start <= to; start += chunk {
		if err := ctx.Err(); err != nil {
			return all, err
		}
		end := start + chunk - 1
		if end > to {
			end = to
		}

		sub := q
		sub.FromBlock = new(big.Int).SetUint64(start)
		sub.ToBlock = new(big.Int).SetUint64(end)

		logs, err := d.client.FilterLogs(ctx, sub)
		if err != nil {
			return nil, fmt.Errorf("chunk [%d,%d]: %w", start, end, err)
		}
		all = append(all, logs...)
	}
	return all, nil
}
