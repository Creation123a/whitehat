package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================
// State Dependency Resolution
// =============================================================

// ReadStateDependencies merges evmole discovery with an ABI-based traversal fallback.
// If evmole finds nothing (or misses standard getters), it attempts to call
// standard interface methods (like ERC-4626 asset()) to ensure the graph isn't severed.
func ReadStateDependencies(
	ctx context.Context,
	client *ethclient.Client,
	addr common.Address,
	code []byte,
	dummyUser common.Address,
) []common.Address {

	// 1. Primary path: evmole-based discovery
	deps := DiscoverLinkedContracts(ctx, client, addr, code, dummyUser)
	
	seen := make(map[common.Address]bool)
	for _, d := range deps {
		seen[d] = true
	}

	// 2. ABI-based fallback: Probe standard interface methods directly.
	// This ensures we find dependencies even if evmole fails to extract the selector map.
	standardGetters := []string{
		"38d52e0f", // asset() -> ERC-4626 underlying
		"01e1d114", // totalAssets()
		"5ec88c79", // comptroller() -> Compound
		"16f0115b", // pool() -> Aave
	}

	for _, sel := range standardGetters {
		callData := common.Hex2Bytes(sel)
		msg := ethereum.CallMsg{To: &addr, Data: callData}
		
		output, err := client.CallContract(ctx, msg, nil)
		if err != nil || len(output) < 32 {
			continue
		}

		candidate := common.BytesToAddress(output[12:32])
		if candidate == (common.Address{}) || candidate == addr || seen[candidate] {
			continue
		}

		candidateCode, err := client.CodeAt(ctx, candidate, nil)
		if err == nil && len(candidateCode) > 0 {
			log.Printf("scanner[state]: Discovered standard dependency via 0x%s: %s", sel, candidate.Hex())
			deps = append(deps, candidate)
			seen[candidate] = true
		}
	}

	return deps
}

// =============================================================
// Vault Asset Resolution
// =============================================================

// GetVaultAsset returns the underlying asset of an ERC-4626 vault.
// Returns the zero address if the call reverts or the contract is not a vault.
func GetVaultAsset(ctx context.Context, client *ethclient.Client, vault common.Address) common.Address {
	// asset() selector: 0x38d52e0f
	callData := common.Hex2Bytes("38d52e0f")
	msg := ethereum.CallMsg{To: &vault, Data: callData}
	
	output, err := client.CallContract(ctx, msg, nil)
	if err != nil || len(output) < 32 {
		return common.Address{}
	}

	asset := common.BytesToAddress(output[12:32])
	if asset == (common.Address{}) {
		return common.Address{}
	}
	
	return asset
}

// =============================================================
// Health Check Resolution
// =============================================================

// ResolveHealthCheckTarget finds the correct contract to call for health checks.
// It returns the address of the contract and its type ("compound" or "aave").
//
// It works by:
//  1. Checking if the given poolAddr already exposes the health check.
//  2. If not, checking for a `comptroller()` or `pool()` getter and probing that address.
func ResolveHealthCheckTarget(
	ctx context.Context,
	client *ethclient.Client,
	poolAddr common.Address,
) (common.Address, string) {

	dummyUser := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Helper to test if an address exposes Compound or Aave health checks
	checkHealthInterface := func(addr common.Address) string {
		// Test Compound: getAccountLiquidity(address) -> 0x5ec88c79
		compData := append(common.Hex2Bytes("5ec88c79"), common.LeftPadBytes(dummyUser.Bytes(), 32)...)
		msg := ethereum.CallMsg{To: &addr, Data: compData}
		if out, err := client.CallContract(ctx, msg, nil); err == nil && len(out) >= 96 {
			return "compound"
		}

		// Test Aave: getUserAccountData(address) -> 0xbf92857c
		aaveData := append(common.Hex2Bytes("bf92857c"), common.LeftPadBytes(dummyUser.Bytes(), 32)...)
		msg = ethereum.CallMsg{To: &addr, Data: aaveData}
		if out, err := client.CallContract(ctx, msg, nil); err == nil && len(out) >= 192 {
			return "aave"
		}

		return ""
	}

	// 1. Check if poolAddr itself is the health check target
	if kind := checkHealthInterface(poolAddr); kind != "" {
		return poolAddr, kind
	}

	// 2. Try comptroller() getter (0x5ec88c79) for Compound forks
	compGetterData := common.Hex2Bytes("5ec88c79")
	msg := ethereum.CallMsg{To: &poolAddr, Data: compGetterData}
	if out, err := client.CallContract(ctx, msg, nil); err == nil && len(out) >= 32 {
		compAddr := common.BytesToAddress(out[12:32])
		if compAddr != (common.Address{}) && compAddr != poolAddr {
			if kind := checkHealthInterface(compAddr); kind != "" {
				return compAddr, kind
			}
		}
	}

	// 3. Try pool() getter (0x16f0115b) for Aave forks
	poolGetterData := common.Hex2Bytes("16f0115b")
	msg = ethereum.CallMsg{To: &poolAddr, Data: poolGetterData}
	if out, err := client.CallContract(ctx, msg, nil); err == nil && len(out) >= 32 {
		aaveAddr := common.BytesToAddress(out[12:32])
		if aaveAddr != (common.Address{}) && aaveAddr != poolAddr {
			if kind := checkHealthInterface(aaveAddr); kind != "" {
				return aaveAddr, kind
			}
		}
	}

	// 4. Try POOL() getter (0x16f0115b) for Aave (some forks capitalize it)
	// Note: Usually POOL() and pool() share the same selector unless the signature differs, 
	// but we check it explicitly just in case.
	poolUpperData := common.Hex2Bytes("16f0115b")
	msg = ethereum.CallMsg{To: &poolAddr, Data: poolUpperData}
	if out, err := client.CallContract(ctx, msg, nil); err == nil && len(out) >= 32 {
		aaveAddr := common.BytesToAddress(out[12:32])
		if aaveAddr != (common.Address{}) && aaveAddr != poolAddr {
			if kind := checkHealthInterface(aaveAddr); kind != "" {
				return aaveAddr, kind
			}
		}
	}

	// If no health check interface is found, return zero address
	fmt.Printf("scanner[state]: Could not resolve health check target for %s\n", poolAddr.Hex())
	return common.Address{}, ""
}
