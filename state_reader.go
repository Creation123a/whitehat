package main

import (
	"context"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Known function selectors that return linked contract addresses
var linkedContractSelectors = map[string]string{
	"0x5fe3b567": "comptroller()",   // Compound / Moonwell / Sonne
	"0x7dc0d1d0": "oracle()",        // Many lending protocols
	"0x16f0115b": "pool()",          // Uniswap V3 / General
	"0x38d52e0f": "asset()",         // ERC-4626
	"0x1f1fcd51": "want()",          // Yearn Vaults
	"0xf808e0f4": "getPool()",       // Balancer
	"0xb3596f07": "getAssetPrice()", // Aave
	"0xfc57d4df": "getUnderlyingPrice()", // Compound
}

// DiscoverLinkedContracts checks the bytecode for known selectors and queries them via RPC.
func DiscoverLinkedContracts(ctx context.Context, client *ethclient.Client, addr common.Address, bytecode []byte) []common.Address {
	hexCode := common.Bytes2Hex(bytecode)
	var discovered []common.Address
	seen := make(map[common.Address]bool)

	for selector, name := range linkedContractSelectors {
		// Check if the selector exists in the bytecode (strip the 0x for string search)
		if strings.Contains(hexCode, selector[2:]) {
			// Prepare eth_call
			callArgs := map[string]interface{}{"to": addr.Hex(), "data": selector}
			var result string
			err := client.Client().CallContext(ctx, &result, "eth_call", callArgs, "latest")
			
			if err == nil && len(result) >= 42 {
				// Parse the address from the result
				linkedAddr := common.BytesToAddress(common.Hex2Bytes(result[2:]))
				if linkedAddr != (common.Address{}) && linkedAddr != addr && !seen[linkedAddr] {
					log.Printf("scanner[state]: Discovered linked contract via %s: %s", name, linkedAddr.Hex())
					discovered = append(discovered, linkedAddr)
					seen[linkedAddr] = true
				}
			}
		}
	}
	return discovered
}
