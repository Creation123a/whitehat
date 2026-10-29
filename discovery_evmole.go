package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"strings"

	evmole "github.com/cdump/evmole/go"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// DiscoverLinkedContracts uses evmole to deterministically discover linked
// contracts by probing no-arg view functions and address-arg functions.
//
// v11.0 Changes:
//   - Replaces 4byte selector guessing with evmole StateMutability/Arguments metadata.
//   - Probes no-arg view functions for single address returns.
//   - Probes address-arg functions with a dummyUser to reach Compound-style health checks.
//   - Decodes address[] array returns for functions like getAllMarkets().
func DiscoverLinkedContracts(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
	code []byte,
	dummyUser common.Address,
) []common.Address {

	var discovered []common.Address
	seen := make(map[common.Address]bool)

	// 1. Extract metadata via evmole
	info, err := evmole.ContractInfo(ctx, code, evmole.Options{
		Selectors:       true,
		Arguments:       true,
		StateMutability: true,
	})
	if err != nil {
		log.Printf("scanner[evmole]: Failed to extract metadata for %s: %v", addr.Hex(), err)
		return nil
	}

	// 2. Iterate and probe
	for _, fn := range info.Functions {
		if fn.StateMutability == nil {
			continue
		}
		
		// Only probe view or pure functions
		mutability := strings.ToLower(*fn.StateMutability)
		if mutability != "view" && mutability != "pure" {
			continue
		}

		needsAddressArg := false
		if fn.Arguments != nil && strings.Contains(*fn.Arguments, "address") {
			needsAddressArg = true
		}

		// Build calldata
		callData := make([]byte, 4)
		binary.BigEndian.PutUint32(callData, fn.Selector)

		if needsAddressArg {
			// Append the dummyUser address (padded to 32 bytes) as the probe argument
			callData = append(callData, common.LeftPadBytes(dummyUser.Bytes(), 32)...)
		}

		// Execute eth_call
		msg := ethereum.CallMsg{To: &addr, Data: callData}
		output, err := client.CallContract(ctx, msg, nil)
		if err != nil || len(output) == 0 {
			continue
		}

		// Decode output
		candidates := decodeAddressOrArray(output)
		for _, candidate := range candidates {
			if candidate == (common.Address{}) || candidate == addr || seen[candidate] {
				continue
			}
			// Verify the candidate actually has bytecode before adding
			candidateCode, err := client.CodeAt(ctx, candidate, nil)
			if err == nil && len(candidateCode) > 0 {
				discovered = append(discovered, candidate)
				seen[candidate] = true
			}
		}
	}

	return discovered
}

// decodeAddressOrArray handles both single address returns and dynamic address[] arrays.
func decodeAddressOrArray(data []byte) []common.Address {
	var result []common.Address

	// Single address return (32 bytes)
	if len(data) == 32 {
		addr := common.BytesToAddress(data[12:32])
		if addr != (common.Address{}) {
			result = append(result, addr)
		}
		return result
	}

	// Dynamic array return (>= 64 bytes)
	// Word 0: Offset to array data (usually 0x20)
	// Word 1: Length of array
	// Word 2..N: Array elements (each padded to 32 bytes)
	if len(data) >= 64 {
		offset := new(big.Int).SetBytes(data[:32]).Uint64()
		if offset == 32 && len(data) >= 64 {
			length := new(big.Int).SetBytes(data[32:64]).Uint64()
			// Sanity check to prevent huge allocations on malicious data
			if length > 0 && length < 1000 {
				for i := uint64(0); i < length; i++ {
					start := 64 + (i * 32)
					end := start + 32
					if end > uint64(len(data)) {
						break
					}
					addr := common.BytesToAddress(data[start+12 : end])
					if addr != (common.Address{}) {
						result = append(result, addr)
					}
				}
			}
		}
	}

	// Static array return fallback (legacy contracts returning address[N] without dynamic offset)
	if len(data) > 32 && len(result) == 0 {
		for i := 0; i+32 <= len(data); i += 32 {
			addr := common.BytesToAddress(data[i+12 : i+32])
			if addr != (common.Address{}) {
				result = append(result, addr)
			}
		}
	}

	return result
}
