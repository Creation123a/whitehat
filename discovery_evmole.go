package main

import (
	"context"
	"log"
	"math/big"
	"strings"

	evmole "github.com/cdump/evmole/go"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func DiscoverLinkedContracts(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
	code []byte,
	dummyUser common.Address,
) []common.Address {

	var discovered []common.Address
	seen := make(map[common.Address]bool)

	info, err := evmole.ContractInfo(ctx, code, evmole.Options{
		Selectors:       true,
		Arguments:       true,
		StateMutability: true,
	})
	if err != nil {
		log.Printf("scanner[evmole]: Failed to extract metadata for %s: %v", addr.Hex(), err)
		return nil
	}

	for _, fn := range info.Functions {
		if fn.StateMutability == nil {
			continue
		}
		
		mutability := strings.ToLower(*fn.StateMutability)
		if mutability != "view" && mutability != "pure" {
			continue
		}

		needsAddressArg := false
		if fn.Arguments != nil && strings.Contains(*fn.Arguments, "address") {
			needsAddressArg = true
		}

		// FIX: fn.Selector is a string. Convert it to 4-byte hex.
		selectorHex := fn.Selector
		if !strings.HasPrefix(selectorHex, "0x") {
			selectorHex = "0x" + selectorHex
		}
		callData := common.FromHex(selectorHex)

		if len(callData) != 4 {
			continue
		}

		if needsAddressArg {
			callData = append(callData, common.LeftPadBytes(dummyUser.Bytes(), 32)...)
		}

		msg := ethereum.CallMsg{To: &addr, Data: callData}
		output, err := client.CallContract(ctx, msg, nil)
		if err != nil || len(output) == 0 {
			continue
		}

		candidates := decodeAddressOrArray(output)
		for _, candidate := range candidates {
			if candidate == (common.Address{}) || candidate == addr || seen[candidate] {
				continue
			}
			candidateCode, err := client.CodeAt(ctx, candidate, nil)
			if err == nil && len(candidateCode) > 0 {
				discovered = append(discovered, candidate)
				seen[candidate] = true
			}
		}
	}

	return discovered
}

func decodeAddressOrArray(data []byte) []common.Address {
	var result []common.Address

	if len(data) == 32 {
		addr := common.BytesToAddress(data[12:32])
		if addr != (common.Address{}) {
			result = append(result, addr)
		}
		return result
	}

	if len(data) >= 64 {
		offset := new(big.Int).SetBytes(data[:32]).Uint64()
		if offset == 32 && len(data) >= 64 {
			length := new(big.Int).SetBytes(data[32:64]).Uint64()
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
