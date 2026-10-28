package main

import (
	"context"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var targetKeywords = []string{
	"pool", "oracle", "comptroller", "manager", 
	"reserve", "lending", "vault", "asset", 
	"want", "config", "strategy", "rate",
}

func DiscoverLinkedContracts(
	ctx context.Context, 
	client *ethclient.Client, 
	addr common.Address, 
	selectorMap map[string]string, 
) []common.Address {
	
	var discovered []common.Address
	seen := make(map[common.Address]bool)

	for selectorHex, functionName := range selectorMap {
		matches := false
		lowerName := strings.ToLower(functionName)
		for _, kw := range targetKeywords {
			if strings.Contains(lowerName, kw) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}

		data := "0x" + selectorHex
		callArgs := map[string]interface{}{"to": addr.Hex(), "data": data}
		
		var result string
		err := client.Client().CallContext(ctx, &result, "eth_call", callArgs, "latest")
		
		if err == nil && len(result) >= 42 {
			linkedAddr := common.BytesToAddress(common.Hex2Bytes(result[2:]))
			
			// CRITICAL FIX: Ensure the returned address actually has bytecode
			if linkedAddr != (common.Address{}) && linkedAddr != addr && !seen[linkedAddr] {
				code, err := client.CodeAt(ctx, linkedAddr, nil)
				if err == nil && len(code) > 0 {
					log.Printf("scanner[state]: Discovered linked contract via %s (0x%s): %s", functionName, selectorHex, linkedAddr.Hex())
					discovered = append(discovered, linkedAddr)
					seen[linkedAddr] = true
				}
			}
		}
	}
	return discovered
}
