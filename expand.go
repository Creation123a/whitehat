package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

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

func ClassifyContract(ctx context.Context, code []byte) (ContractRole, map[string]int) {
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
		for i := 0; i+5 <= len(code); i++ {
			if code[i] == 0x63 { // PUSH4
				selCounts[hex.EncodeToString(code[i+1:i+5])]++
			}
		}
	}

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

	mathHits := 0
	for sel := range selCounts {
		if sel == "0de0b6b3" || sel == "771602f7" || sel == "1a686502" {
			mathHits++
		}
	}

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
// that match known factory event signatures using eth_getLogs.
func ScanFactoryEvents(
	ctx context.Context,
	client *ethclient.Client,
	factory common.Address,
	fromBlock *big.Int,
	toBlock *big.Int,
) []common.Address {

	var topic0 []common.Hash
	for _, sig := range FactoryEventSignatures {
		topic0 = append(topic0, crypto.Keccak256Hash([]byte(sig)))
	}

	query := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   toBlock,
		Addresses: []common.Address{factory},
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

// =============================================================
// SQD Portal Discovery (RPC-Free)
// =============================================================

// ScanFactoryEventsSQD uses the SQD Portal to fetch full historical factory events
// without touching your RPC provider.
func ScanFactoryEventsSQD(ctx context.Context, factory common.Address, topic0Hash common.Hash) ([]common.Address, error) {
	url := "https://portal.sqd.dev/datasets/base-mainnet/stream"

	var allFound []common.Address
	seen := make(map[common.Address]bool)
	fromBlock := uint64(0)
	toBlock := uint64(99999999) // Catch all historical and recent blocks

	for {
		select {
		case <-ctx.Done():
			return allFound, ctx.Err()
		default:
		}

		reqBody := map[string]interface{}{
			"type":      "evm",
			"fromBlock": fromBlock,
			"toBlock":   toBlock,
			"logs": []map[string]interface{}{
				{
					"address": []string{factory.Hex()},
					"topic0":  []string{topic0Hash.Hex()},
				},
			},
			"fields": map[string]interface{}{
				"log": map[string]bool{
					"address": true,
					"topics":  true,
					"data":    true,
				},
			},
		}

		bodyBytes, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return allFound, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return allFound, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return allFound, fmt.Errorf("SQD API error %d: %s", resp.StatusCode, string(body))
		}

		scanner := bufio.NewScanner(resp.Body)
		lastBlockInStream := fromBlock

		for scanner.Scan() {
			var chunk struct {
				Header struct {
					Number uint64 `json:"number"`
				} `json:"header"`
				Logs []struct {
					Topics []string `json:"topics"`
					Data   string   `json:"data"`
				} `json:"logs"`
			}
			
			if err := json.Unmarshal(scanner.Bytes(), &chunk); err != nil {
				continue
			}

			lastBlockInStream = chunk.Header.Number

			for _, logEntry := range chunk.Logs {
				// 1. Check indexed topics
				for _, topic := range logEntry.Topics[1:] {
					if len(topic) == 66 { // 0x + 64 hex chars
						addr := common.HexToAddress(topic)
						if addr != (common.Address{}) && !seen[addr] {
							seen[addr] = true
							allFound = append(allFound, addr)
						}
					}
				}
				
				// 2. Check non-indexed data payload
				if len(logEntry.Data) > 2 {
					dataBytes := common.FromHex(logEntry.Data)
					for i := 0; i+32 <= len(dataBytes); i += 32 {
						word := dataBytes[i : i+32]
						// Check if it looks like a padded address (first 12 bytes zero)
						if bytes.Equal(word[:12], make([]byte, 12)) {
							addr := common.BytesToAddress(word[12:])
							if addr != (common.Address{}) && !seen[addr] {
								seen[addr] = true
								allFound = append(allFound, addr)
							}
						}
					}
				}
			}
		}
		resp.Body.Close()

		// Pagination check
		if lastBlockInStream >= toBlock {
			break
		}
		fromBlock = lastBlockInStream + 1
	}

	if len(allFound) > 0 {
		log.Printf("scanner[sqd]: Found %d historical child contracts for factory %s", len(allFound), factory.Hex())
	}
	return allFound, nil
}

// IsFactoryCandidateBytecode checks if the bytecode contains a PUSH32 of
// any known factory event topic hash.
func IsFactoryCandidateBytecode(code []byte) bool {
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
