package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

type FuzzResult struct {
	InvariantBroken bool
	Invariant       string
	Counterexample  string
	Output          string
}

// RunMedusaFuzz generates a wrapper invariant file for the target role,
// then runs Medusa against it. Returns true if any invariant is broken.
func RunMedusaFuzz(ctx context.Context, target common.Address, role ContractRole, rpcURL string, blockNum uint64) (*FuzzResult, error) {
	// 1. Generate the invariant Solidity file
	invariants := generateInvariants(role, target)
	if invariants == "" {
		return nil, fmt.Errorf("no invariants defined for role %s", role)
	}

	// 2. Write to temp workspace
	tmpDir, err := os.MkdirTemp("", "medusa-fuzz")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	invFile := filepath.Join(tmpDir, "Invariants.sol")
	if err := os.WriteFile(invFile, []byte(invariants), 0644); err != nil {
		return nil, err
	}

	// 3. Medusa config
	// NOTE: Medusa defaults to the `fuzz_` prefix for property functions.
	// Our invariants use `check_`, so we must explicitly list it in testPrefixes.
	configFile := filepath.Join(tmpDir, "medusa.json")
	config := map[string]interface{}{
		"fuzzing": map[string]interface{}{
			"timeout":         300, // 5 minutes per target
			"targetContracts": []string{"Invariants"},
			"testLimit":       100000,
			"propertyTesting": map[string]interface{}{
				"enabled":      true,
				"testPrefixes": []string{"check_", "invariant_"},
			},
			"coverageEnabled": true,
		},
		"compilation": map[string]interface{}{
			"sources":  []string{tmpDir},
			"platform": "crytic-compile", // default, but explicit is better
		},
		"chain": map[string]interface{}{
			"rpcURL":      rpcURL,
			"blockNumber": blockNum,
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, configBytes, 0644)

	// 4. Run Medusa
	cmd := exec.CommandContext(ctx, "medusa", "fuzz", "--config", configFile)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// 5. Parse for invariant failures
	result := &FuzzResult{Output: outStr}
	if strings.Contains(outStr, "assertion failed") || strings.Contains(outStr, "Failed!") || strings.Contains(outStr, "FAILED") {
		result.InvariantBroken = true
		for _, line := range strings.Split(outStr, "\n") {
			if strings.Contains(line, "assertion") || strings.Contains(line, "invariant") || strings.Contains(line, "FAILED") {
				result.Invariant = strings.TrimSpace(line)
				result.Counterexample = line
				break
			}
		}
	}

	return result, err
}

func generateInvariants(role ContractRole, target common.Address) string {
	header := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {
`
	footer := fmt.Sprintf(`
}

contract Invariants {
    ITarget constant target = ITarget(%s);
`, target.Hex())

	switch role {
	case RoleLending:
		return header + `
    function totalBorrows() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function getCash() external view returns (uint256);
` + footer + `
    // Structural bound: borrows must never exceed supply by more than
    // 1% (allows for reserve accrual). A violation means accounting was
    // manipulated or shares were inflated without corresponding deposits.
    function check_borrows_bounded() public view {
        try target.totalSupply() returns (uint256 supply) {
            try target.totalBorrows() returns (uint256 borrows) {
                require(
                    borrows <= (supply * 101) / 100,
                    "BORROWS_EXCEED_SUPPLY"
                );
            } catch {}
        } catch {}
    }

    // Cash should never exceed supply (cash + borrows == supply + reserves
    // in a healthy market). More cash than supply means phantom assets.
    function check_cash_bounded() public view {
        try target.totalSupply() returns (uint256 supply) {
            try target.getCash() returns (uint256 cash) {
                require(
                    cash <= (supply * 101) / 100,
                    "CASH_EXCEEDS_SUPPLY"
                );
            } catch {}
        } catch {}
    }
}
`
	case RoleVault:
		return header + `
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
` + footer + `
    uint256 private _maxSharePrice;
    uint256 private _initialPrice;
    bool private _initialized;

    // Self-initializing baseline. Medusa may not call setup(), so we
    // capture the baseline on the first invariant check instead.
    function _initBaseline() internal {
        if (_initialized) return;
        try target.totalSupply() returns (uint256 supply) {
            if (supply > 0) {
                try target.totalAssets() returns (uint256 assets) {
                    _initialPrice = (assets * 1e18) / supply;
                    _maxSharePrice = _initialPrice;
                } catch {}
            }
        } catch {}
        _initialized = true;
    }

    // Share price (assets per share) should never decrease across operations.
    // A decrease means someone extracted value they didn't earn — either via
    // rounding in their favor, a donation attack, or a share dilution bug.
    function check_share_price_monotonic() public {
        _initBaseline();
        if (_maxSharePrice == 0) return;
        try target.totalSupply() returns (uint256 supply) {
            if (supply == 0) return;
            try target.totalAssets() returns (uint256 assets) {
                require(assets > 0, "SHARES_WITHOUT_ASSETS");
                uint256 price = (assets * 1e18) / supply;
                require(price >= _maxSharePrice, "SHARE_PRICE_DROPPED");
                if (price > _maxSharePrice) {
                    _maxSharePrice = price;
                }
            } catch {}
        } catch {}
    }

    // Classic ERC-4626 1-wei inflation: attacker inflates price by >100x,
    // then victim deposits get rounded to 0 shares. This catches the state
    // that must exist for that attack to succeed.
    function check_price_not_inflated() public {
        _initBaseline();
        if (_initialPrice == 0) return;
        try target.totalSupply() returns (uint256 supply) {
            if (supply == 0) return;
            try target.totalAssets() returns (uint256 assets) {
                uint256 price = (assets * 1e18) / supply;
                require(price <= _initialPrice * 100, "PRICE_INFLATED_100X");
            } catch {}
        } catch {}
    }

    // Round-trip must favor the protocol. If converting deposits to shares
    // and back yields MORE than the original deposit, an attacker can
    // extract value by looping.
    function check_roundtrip_favors_protocol() public view {
        try target.convertToShares(1) returns (uint256 s1) {
            try target.convertToAssets(s1) returns (uint256 a1) {
                require(a1 <= 1, "RT_1");
            } catch {}
        } catch {}
        try target.convertToShares(1e6) returns (uint256 s2) {
            try target.convertToAssets(s2) returns (uint256 a2) {
                require(a2 <= 1e6, "RT_1e6");
            } catch {}
        } catch {}
        try target.convertToShares(1e18) returns (uint256 s3) {
            try target.convertToAssets(s3) returns (uint256 a3) {
                require(a3 <= 1e18, "RT_1e18");
            } catch {}
        } catch {}
    }
}
`
	case RoleAMM:
		return header + `
    function getReserves() external view returns (uint112, uint112, uint32);
` + footer + `
    uint256 private _maxK;

    // Reserves should never be zero (drain attack). Between checks, K must
    // not shrink by more than 50% — catches flash manipulation that would
    // ordinarily leave <50% of the pre-existing liquidity.
    function check_k_not_drained() public {
        try target.getReserves() returns (uint112 r0, uint112 r1, uint32 unusedTs) {
            require(r0 > 0, "RESERVE_0_ZERO");
            require(r1 > 0, "RESERVE_1_ZERO");

            uint256 k = uint256(r0) * uint256(r1);
            if (_maxK > 0) {
                require(k >= _maxK / 2, "K_HALVED");
            }
            if (k > _maxK) {
                _maxK = k;
            }
        } catch {}
    }
}
`
	}
	return ""
}
