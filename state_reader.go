package main

import (
	"context"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Keywords that indicate a function likely returns a linked contract address
// (e.g., oracle(), getLendingPool(), comptroller(), manager(), asset()).
var targetKeywords = []string{
	"pool", "oracle", "comptroller", "manager", 
	"reserve", "lending", "vault", "asset", 
	"want", "config", "strategy", "rate",
}

// DiscoverLinkedContracts checks the dynamically resolved selector map 
// and queries the contract via RPC for any function matching our keywords.
func DiscoverLinkedContracts(
	ctx context.Context, 
	client *ethclient.Client, 
	addr common.Address, 
	selectorMap map[string]string, // Passed from selector_extractor.go
) []common.Address {
	
	var discovered []common.Address
	seen := make(map[common.Address]bool)

	for selectorHex, functionName := range selectorMap {
		// 1. Check if the function name matches our target keywords
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

		// 2. Prepare eth_call (selectorHex comes without '0x' from the extractor)
		data := "0x" + selectorHex
		callArgs := map[string]interface{}{"to": addr.Hex(), "data": data}
		
		var result string
		err := client.Client().CallContext(ctx, &result, "eth_call", callArgs, "latest")
		
		// 3. Parse the address from the result
		if err == nil && len(result) >= 42 {
			// result is a 32-byte hex string (e.g., 0x000000000000000000000000<20-byte-address>)
			linkedAddr := common.BytesToAddress(common.Hex2Bytes(result[2:]))
			
			// 4. Validate and append
			if linkedAddr != (common.Address{}) && linkedAddr != addr && !seen[linkedAddr] {
				log.Printf("scanner[state]: Discovered linked contract via %s (0x%s): %s", functionName, selectorHex, linkedAddr.Hex())
				discovered = append(discovered, linkedAddr)
				seen[linkedAddr] = true
			}
		}
	}
	return discovered
}
