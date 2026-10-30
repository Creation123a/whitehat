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
	"strconv"
	"strings"
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
//
// Fix B: Always run the raw bytecode scan first. evmole is
// additive enrichment, not the primary source. The old logic
// returned an empty selector map when evmole succeeded but
// returned zero functions (common for proxy-heavy contracts),
// causing RoleLending markets to fall through to RoleUnknown.

func ClassifyContract(ctx context.Context, code []byte) (ContractRole, map[string]int) {
	selCounts := make(map[string]int)

	// 1. Always scan raw bytecode for PUSH4 selectors.
	for i := 0; i+5 <= len(code); i++ {
		if code[i] == 0x63 { // PUSH4
			selCounts[hex.EncodeToString(code[i+1:i+5])]++
		}
	}

	// 2. Enrich with evmole metadata when available. This adds
	// functions that evmole discovers via a different code path
	// (rare, but possible with certain jump-table patterns).
	info, err := evmole.ContractInfo(ctx, code, evmole.Options{
		Selectors:       true,
		Arguments:       true,
		StateMutability: true,
	})
	// In ClassifyContract, replace the evmole enrichment block:
if err == nil && info != nil && len(info.Functions) > 0 {
	for _, fn := range info.Functions {
		sel := strings.TrimPrefix(strings.ToLower(fn.Selector), "0x")
		if len(sel) == 8 {
			selCounts[sel]++
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
// SQD Portal Discovery (RPC-Free, Batched, Cached, Retried)
// =============================================================

// sqdCache prevents re-querying the same factory within a single run.
// Keyed by factory address.
var sqdCache = make(map[common.Address][]common.Address)

// ScanFactoryEventsSQD wraps sqdFetch with retry/backoff for rate limits.
// Honors the Retry-After header on 429/503/529, caps total retries at 5.
func ScanFactoryEventsSQD(ctx context.Context, factory common.Address, topic0Hashes []common.Hash) ([]common.Address, error) {
	if cached, ok := sqdCache[factory]; ok {
		log.Printf("scanner[sqd]: cache hit for factory %s (%d children)", factory.Hex(), len(cached))
		return cached, nil
	}

	var topic0Strings []string
	for _, h := range topic0Hashes {
		topic0Strings = append(topic0Strings, h.Hex())
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			log.Printf("scanner[sqd]: retry %d/5 after %v for factory %s", attempt, backoff, factory.Hex())
			time.Sleep(backoff)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		addrs, retryAfter, err := sqdFetch(ctx, factory, topic0Strings)
		if err == nil {
			sqdCache[factory] = addrs
			return addrs, nil
		}
		lastErr = err

		if retryAfter > 0 {
			log.Printf("scanner[sqd]: rate-limited, honoring Retry-After %v", retryAfter)
			time.Sleep(retryAfter)
		} else if !strings.Contains(err.Error(), "529") &&
			!strings.Contains(err.Error(), "503") &&
			!strings.Contains(err.Error(), "429") {
			// Non-retryable error (e.g. malformed request), stop early
			break
		}
	}
	return nil, lastErr
}

// sqdFetch performs the actual HTTP + NDJSON pagination. It returns
// (addresses, retryAfter, error). On 429/503/529 it returns the
// parsed Retry-After delay so the caller can honor it.
func sqdFetch(ctx context.Context, factory common.Address, topic0Strings []string) ([]common.Address, time.Duration, error) {
	url := "https://portal.sqd.dev/datasets/base-mainnet/stream"

	var allFound []common.Address
	seen := make(map[common.Address]bool)
	fromBlock := uint64(0)
	toBlock := uint64(99999999)

	for {
		select {
		case <-ctx.Done():
			return allFound, 0, ctx.Err()
		default:
		}

		reqBody := map[string]interface{}{
			"type":      "evm",
			"fromBlock": fromBlock,
			"toBlock":   toBlock,
			"logs": []map[string]interface{}{
				{
					"address": []string{factory.Hex()},
					"topic0":  topic0Strings,
				},
			},
			"fields": map[string]interface{}{
				"log": map[string]bool{"address": true, "topics": true, "data": true},
			},
		}

		bodyBytes, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return allFound, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return allFound, 0, err
		}

		// 204 = no matching blocks in the requested range. Not an error.
		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			return allFound, 0, nil
		}

		// Rate limit / server overload — surface Retry-After.
		if resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 529 {
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return allFound, retryAfter, fmt.Errorf("SQD API error %d: %s", resp.StatusCode, string(body))
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return allFound, 0, fmt.Errorf("SQD API error %d: %s", resp.StatusCode, string(body))
		}

		// NDJSON stream. Increase buffer to 10MB to survive very wide logs.
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)
		lastBlockInStream := int64(-1)

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

			lastBlockInStream = int64(chunk.Header.Number)

			for _, logEntry := range chunk.Logs {
				// 1. Indexed topics
				for _, topic := range logEntry.Topics[1:] {
					if len(topic) == 66 {
						addr := common.HexToAddress(topic)
						if addr != (common.Address{}) && !seen[addr] {
							seen[addr] = true
							allFound = append(allFound, addr)
						}
					}
				}

				// 2. Non-indexed data payload
				if len(logEntry.Data) > 2 {
					dataBytes := common.FromHex(logEntry.Data)
					for i := 0; i+32 <= len(dataBytes); i += 32 {
						word := dataBytes[i : i+32]
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

		// Infinite loop protection: if no blocks were returned, stop.
		if lastBlockInStream == -1 || uint64(lastBlockInStream) >= toBlock {
			break
		}

		fromBlock = uint64(lastBlockInStream) + 1
	}

	if len(allFound) > 0 {
		log.Printf("scanner[sqd]: found %d historical child contracts for factory %s", len(allFound), factory.Hex())
	}
	return allFound, 0, nil
}

// parseRetryAfter parses the Retry-After header into a Duration.
// SQD sends this in seconds (per the Portal docs). Capped at 60s
// so a single request cannot stall the pipeline.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		if secs > 60 {
			secs = 60
		}
		return time.Duration(secs) * time.Second
	}
	return 0
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
