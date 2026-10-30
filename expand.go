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
	"net/http"
	"strconv"
	"strings"
	"time"

	evmole "github.com/cdump/evmole/go"
	"github.com/ethereum/go-ethereum/common"
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
	"feaf968c", "50d25bcd", "98d5fdca", "b3596f07", "fc57d4df", "a035b1fe",
}

var AMMSelectors = []string{
	"0902f1ac", // getReserves() — Uniswap V2
	"3850c7bd", // slot0() — Uniswap V3 / Solidly
	"0dfe1681", // token0()
	"d21220a7", // token1()
	"1a686502", // sqrtPriceX96
	"bb7b8b80", // get_virtual_price() — Curve
	"f94d4668", // getPoolTokens(bytes32) — Balancer
}

var LendingSelectors = []string{
	"5ec88c79", "3b1d21a2", "17bfdfbc", "c5ebeaec", "0e752702", "bf92857c",
}

var VaultSelectors = []string{
	"07a2d13a", "c6e6f592", "01e1d114", "4cdad506", "6e553f65", "ba087652",
}

var TokenSelectors = []string{
	"a9059cbb", "095ea7b3", "18160ddd", "70a08231", "23b872dd", "dd62ed3e",
}

// =============================================================
// ClassifyContract
// =============================================================

func ClassifyContract(ctx context.Context, code []byte) (ContractRole, map[string]int) {
	selCounts := make(map[string]int)

	for i := 0; i+5 <= len(code); i++ {
		if code[i] == 0x63 {
			selCounts[hex.EncodeToString(code[i+1:i+5])]++
		}
	}

	info, err := evmole.ContractInfo(ctx, code, evmole.Options{
		Selectors:       true,
		Arguments:       true,
		StateMutability: true,
	})
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
	"PairCreated(address,address,address,uint256)",
	"PairCreated(address,address,bool,address)",
	"PairCreated(address,address,bool,address,uint256)",
	"PoolCreated(address,address,uint24,int24,address)",
	"MarketListed(address)",
	"MarketCreated(address,address)",
	"CreateMarket(bytes32,address)",
	"VaultCreated(address,address)",
	"VaultCreated(address)",
	"NewVault(address)",
	"Deployed(address,address)",
	"Create(address,address)",
	"ProxyCreated(address)",
}

// =============================================================
// SQD Portal Discovery (RPC-Free, Batched, Cached, Retried)
// =============================================================

var sqdCache = make(map[common.Address][]common.Address)

func ScanFactoryEventsSQD(ctx context.Context, factory common.Address, topic0Hashes []common.Hash, currentBlock uint64) ([]common.Address, error) {
	if cached, ok := sqdCache[factory]; ok {
		return cached, nil
	}
	if len(sqdCache) > 5000 {
		log.Printf("scanner[sqd]: cache size cap reached; clearing")
		sqdCache = make(map[common.Address][]common.Address)
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

		addrs, retryAfter, err := sqdFetch(ctx, factory, topic0Strings, currentBlock)
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
			break
		}
	}
	return nil, lastErr
}

func sqdFetch(ctx context.Context, factory common.Address, topic0Strings []string, currentBlock uint64) ([]common.Address, time.Duration, error) {
	url := "https://portal.sqd.dev/datasets/base-mainnet/stream"

	var allFound []common.Address
	seen := make(map[common.Address]bool)

	fromBlock := uint64(0)
	if currentBlock > 5_000_000 {
		fromBlock = currentBlock - 5_000_000
	}
	toBlock := currentBlock

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

		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			return allFound, 0, nil
		}

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
				for _, topic := range logEntry.Topics[1:] {
					if len(topic) == 66 {
						addr := common.HexToAddress(topic)
						if addr != (common.Address{}) && !seen[addr] {
							seen[addr] = true
							allFound = append(allFound, addr)
						}
					}
				}

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
