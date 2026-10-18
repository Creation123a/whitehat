package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// MathKeywords are function names that likely return dependencies (oracles, managers)
var MathKeywords = []string{"oracle", "comptroller", "manager", "strategy", "price", "rate", "vault", "config"}

// FetchABI grabs the contract ABI from Etherscan.
func FetchABI(ctx context.Context, addr common.Address) (string, error) {
	q := url.Values{}
	q.Set("chainid", fmt.Sprintf("%d", EtherscanChainID))
	q.Set("module", "contract")
	q.Set("action", "getabi")
	q.Set("address", addr.Hex())
	q.Set("apikey", EtherscanAPIKey)

	resp, err := http.Get(EtherscanBaseURL + "?" + q.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var res struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.Status != "1" {
		return "", fmt.Errorf("failed to fetch ABI")
	}
	return res.Result, nil
}

// ReadStateDependencies uses the ABI to find and query dependent addresses.
func ReadStateDependencies(ctx context.Context, client *ethclient.Client, addr common.Address) []common.Address {
	abiStr, err := FetchABI(ctx, addr)
	if err != nil {
		return nil
	}

	parsedABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil
	}

	var discovered []common.Address
	seen := make(map[common.Address]bool)

	for _, method := range parsedABI.Methods {
		// Only look at view/pure functions that return a single address
		if method.StateMutability != "view" && method.StateMutability != "pure" {
			continue
		}
		if len(method.Outputs) != 1 || method.Outputs[0].Type.String() != "address" {
			continue
		}

		// Check if the function name matches math/oracle keywords
		matches := false
		lowerName := strings.ToLower(method.Name)
		for _, kw := range MathKeywords {
			if strings.Contains(lowerName, kw) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}

		// Execute eth_call to get the address
		data, err := parsedABI.Pack(method.Name)
		if err != nil {
			continue
		}

		callMsg := ethereum.CallMsg{To: &addr, Data: data}
		result, err := client.CallContract(ctx, callMsg, nil)
		if err != nil || len(result) == 0 {
			continue
		}

		// Parse the address from the 32-byte result
		resAddr := common.BytesToAddress(result[20:])
		if resAddr != (common.Address{}) && !seen[resAddr] {
			seen[resAddr] = true
			discovered = append(discovered, resAddr)
		}
	}
	return discovered
}
