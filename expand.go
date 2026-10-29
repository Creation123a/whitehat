package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	evmole "github.com/cdump/evmole/go"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================
// Contract Roles
// =============================================================

type ContractRole string

const (
	RoleUnknown    ContractRole = "unknown"
	RoleToken      ContractRole = "token"
	RoleAMM        ContractRole = "amm"
	RoleMathOracle ContractRole = "math-oracle"
	RoleLending    ContractRole = "lending"
	RoleVault      ContractRole = "vault"
	RoleFactory    ContractRole = "factory"
)

// =============================================================
// Selector Taxonomy
// =============================================================

var OracleSelectors = []string{
	"feaf968c", // latestRoundData()
	"50d25bcd", // latestAnswer()
	"98d5fdca", // getPrice()
	"b3596f07", // getAssetPrice(address)
	"fc57d4df", // getUnderlyingPrice(address)
	"a035b1fe", // price()
}

var AMMSelectors = []string{
	"0902f1ac", // getReserves()
	"3850c7bd", // slot0()
	"0dfe1681", // token0()
	"d21220a7", // token1()
	"1a686502", // sqrtPriceX96
}

var LendingSelectors = []string{
	"5ec88c79", // getAccountLiquidity(address)
	"3b1d21a2", // getCash()
	"17bfdfbc", // borrowBalanceStored(address)
	"c5ebeaec", // borrow(uint256)
	"0e752702", // repayBorrow(uint256)
	"bf92857c", // getUserAccountData(address) [Aave V3]
}

var VaultSelectors = []string{
	"07a2d13a", // convertToAssets(uint256)
	"c6e6f592", // convertToShares(uint256)
	"01e1d114", // totalAssets()
	"4cdad506", // previewRedeem(uint256)
	"6e553f65", // deposit(uint256,address)
	"ba087652", // redeem(uint256,address,address)
}

var TokenSelectors = []string{
	"a9059cbb", // transfer
	"095ea7b3", // approve
	"18160ddd", // totalSupply
	"70a08231", // balanceOf
	"23b872dd", // transferFrom
	"dd62ed3e", // allowance
}

// =============================================================
// ClassifyContract
// =============================================================

// ClassifyContract uses evmole to extract function selectors and classifies
// the contract based on the presence of known selector combinations.
func ClassifyContract(ctx context.Context, code []byte) (ContractRole, map[string]int) {
	// 1. Extract selectors using evmole
	info, err := evmole.ContractInfo(ctx, code, evmole.Options{
		Selectors:       true,
		Arguments:       true,
		StateMutability: true,
	})
	
	selCounts := make(map[string]int)
	if err == nil && info != nil {
		for _, fn := range info.Functions {
			selCounts[fmt.Sprintf("%08x", fn.Selector)]++
		}
	} else {
		// Fallback: raw bytecode scan if evmole fails
		for i := 0; i+5 <= len(code); i++ {
			if code[i] == 0x63 { // PUSH4
				selCounts[hex.EncodeToString(code[i+1:i+5])]++
			}
		}
	}

	// 2. Count matches against taxonomy
	matches := func(taxonomy []string) int {
		count := 0
		for _, sel := range taxonomy {
			if selCounts[sel] > 0 {
				count++
			}
		}
		return count
	}

	vaultHits := matches(VaultSelectors)
	lendingHits := matches(LendingSelectors)
	oracleHits := matches(OracleSelectors)
	ammHits := matches(AMMSelectors)
	tokenHits := matches(TokenSelectors)

	// Check for any math selectors (generic math operations that might indicate an oracle or pricing logic)
	mathHits := 0
	for sel := range selCounts {
		if sel == "0de0b6b3" || sel == "771602f7" || sel == "1a686502" { // selectors for common math functions or sqrtPrice
			mathHits++
		}
	}

		// 3. Priority classification
	var role ContractRole
	switch {
	case vaultHits >= 2:
		role = RoleVault
	case lendingHits > 0:
		role = RoleLending
	case ammHits > 0:
		role = RoleAMM
	case mathHits > 0 || oracleHits > 0:
		role = RoleMathOracle
	case tokenHits >= 3 && mathHits == 0 && oracleHits == 0:
		role = RoleToken
	default:
		role = RoleUnknown
	}
	return role, selCounts
}

// =============================================================
// Factory Events
// =============================================================

var FactoryEventSignatures = []string{
	"PairCreated(address,address,address,uint256)",      // Uniswap V2
	"PairCreated(address,address,bool,address)",         // Aerodrome 4-arg
	"PairCreated(address,address,bool,address,uint256)", // Aerodrome 5-arg
	"PoolCreated(address,address,uint24,int24,address)", // Uniswap V3
	"MarketListed(address)",                             // Compound
	"MarketCreated(address,address)",
	"CreateMarket(bytes32,address)",                     // Morpho
	"VaultCreated(address,address)",
	"VaultCreated(address)",
	"NewVault(address)",
	"Deployed(address,address)",
	"Create(address,address)",
	"ProxyCreated(address)",
}

// ScanFactoryEvents searches for logs emitted by the given factory contract
// that match known factory event signatures. It returns verified contract addresses.
func ScanFactoryEvents(
	ctx context.Context,
	client *ethclient.Client,
	factory common.Address,
	fromBlock *big.Int,
	toBlock *big.Int,
) []common.Address {

	// FIX: Build a single slice of hashes for Topic 0
	var topic0 []common.Hash
	for _, sig := range FactoryEventSignatures {
		topic0 = append(topic0, crypto.Keccak256Hash([]byte(sig)))
	}

	query := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   toBlock,
		Addresses: []common.Address{factory},
		// FIX: Wrap the single slice of hashes in a slice of slices
		Topics:    [][]common.Hash{topic0},
	}

	logs, err := client.FilterLogs(ctx, query)
	if err != nil {
		return nil
	}

	seen := make(map[common.Address]bool)
	var found []common.Address

	extractAddressFromWord := func(word common.Hash) common.Address {
		if common.BytesToHash(word[:12]) == (common.Hash{}) {
			return common.BytesToAddress(word[12:])
		}
		return common.Address{}
	}

	for _, vLog := range logs {
		for _, topic := range vLog.Topics[1:] {
			addr := extractAddressFromWord(topic)
			if addr != (common.Address{}) && !seen[addr] {
				if code, err := client.CodeAt(ctx, addr, nil); err == nil && len(code) > 0 {
					found = append(found, addr)
					seen[addr] = true
				}
			}
		}

		for i := 0; i+32 <= len(vLog.Data); i += 32 {
			word := common.BytesToHash(vLog.Data[i : i+32])
			addr := extractAddressFromWord(word)
			if addr != (common.Address{}) && !seen[addr] {
				if code, err := client.CodeAt(ctx, addr, nil); err == nil && len(code) > 0 {
					found = append(found, addr)
					seen[addr] = true
				}
			}
		}
	}

	if len(found) > 0 {
		log.Printf("scanner[factory]: Found %d contracts emitted by factory %s", len(found), factory.Hex())
	}

	return found
}
// IsFactoryCandidateBytecode checks if the bytecode contains a PUSH32 of
// any known factory event topic hash. This avoids source-level heuristics.
func IsFactoryCandidateBytecode(code []byte) bool {
	// Precompute topic hashes
	topicMap := make(map[common.Hash]bool)
	for _, sig := range FactoryEventSignatures {
		topicMap[crypto.Keccak256Hash([]byte(sig))] = true
	}

	for i := 0; i+33 <= len(code); i++ {
		if code[i] == 0x7f { // PUSH32
			var hash common.Hash
			copy(hash[:], code[i+1:i+33])
			if topicMap[hash] {
				return true
			}
		}
	}
	return false
}
