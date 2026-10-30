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

func RunMedusaFuzz(ctx context.Context, target common.Address, role ContractRole, rpcURL string, blockNum uint64) (*FuzzResult, error) {
	invariants := generateInvariants(role, target)
	if invariants == "" {
		return nil, fmt.Errorf("no invariants for role %s", role)
	}

	tmpDir, err := os.MkdirTemp("", "medusa-fuzz")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	invFile := filepath.Join(tmpDir, "Invariants.sol")
	if err := os.WriteFile(invFile, []byte(invariants), 0644); err != nil {
		return nil, fmt.Errorf("write invariants: %w", err)
	}

	// C6 FIX: propertyTesting is under fuzzing.testing, NOT fuzzing directly.
	// targetContracts points to "Invariants" (which includes a Harness section).
	config := map[string]interface{}{
		"fuzzing": map[string]interface{}{
			"workers":            4,
			"timeout":            300,
			"testLimit":          100000,
			"callSequenceLength": 50,
			"coverageEnabled":    true,
			"targetContracts":    []string{"Invariants"},
			"targetContractsBalances": []string{
				// Give the harness ETH so it can fund deposit calls
				"1000000000000000000000000", // 1M ETH
			},
			"testing": map[string]interface{}{
				"stopOnFailedTest": true,
				"propertyTesting": map[string]interface{}{
					"enabled":      true,
					"testPrefixes": []string{"check_"},
				},
				"assertionTesting": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		"compilation": map[string]interface{}{
			"platform": "crytic-compile",
			"platformConfig": map[string]interface{}{
				"target":      ".",
				"solcVersion": "0.8.20",
			},
		},
		"chainConfig": map[string]interface{}{
			"rpcURL":      rpcURL,
			"blockNumber": fmt.Sprintf("%d", blockNum),
		},
	}

	configBytes, _ := json.MarshalIndent(config, "", "  ")
	configFile := filepath.Join(tmpDir, "medusa.json")
	if err := os.WriteFile(configFile, configBytes, 0644); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	cmd := exec.CommandContext(ctx, "medusa", "fuzz", "--config", configFile)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	result := &FuzzResult{Output: outStr}
	if strings.Contains(outStr, "assertion failed") ||
		strings.Contains(outStr, "Failed!") ||
		strings.Contains(outStr, "FAILED") ||
		strings.Contains(outStr, "failed") {
		result.InvariantBroken = true
		for _, line := range strings.Split(outStr, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(line, "assertion") || strings.Contains(line, "invariant") || strings.Contains(line, "FAILED") {
				result.Invariant = trimmed
				result.Counterexample = line
				break
			}
		}
	}

	return result, err
}

func generateInvariants(role ContractRole, target common.Address) string {
	header := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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
    function borrow(uint256) external;
    function repayBorrow(uint256) external;
` + footer + `
    // HARNESS: state-changing functions Medusa calls on the target
    function harness_borrow(uint256 amount) public {
        target.borrow(amount);
    }
    function harness_repay(uint256 amount) public {
        target.repayBorrow(amount);
    }

    function check_borrows_bounded() public view {
        try target.totalSupply() returns (uint256 supply) {
            try target.totalBorrows() returns (uint256 borrows) {
                require(borrows <= (supply * 101) / 100, "BORROWS_EXCEED_SUPPLY");
            } catch {}
        } catch {}
    }

    function check_cash_bounded() public view {
        try target.totalSupply() returns (uint256 supply) {
            try target.getCash() returns (uint256 cash) {
                require(cash <= (supply * 101) / 100, "CASH_EXCEEDS_SUPPLY");
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
    function deposit(uint256, address) external;
    function withdraw(uint256, address, address) external;
    function asset() external view returns (address);
    function balanceOf(address) external view returns (uint256);
` + footer + `
    uint256 private _maxSharePrice;
    uint256 private _initialPrice;
    bool private _initialized;

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

    // HARNESS: state-changing functions Medusa calls
    function harness_deposit(uint256 amount) public {
        _initBaseline();
        address asset = target.asset();
        // Approve is handled by Medusa's token balance setup
        target.deposit(amount, address(this));
    }
    function harness_withdraw(uint256 shares) public {
        _initBaseline();
        target.withdraw(shares, address(this), address(this));
    }

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
    function swap(uint256, uint256, address, bytes) external;
` + footer + `
    uint256 private _maxK;

    // HARNESS: state-changing swap function
    function harness_swap(uint256 amount0Out, uint256 amount1Out) public {
        target.swap(amount0Out, amount1Out, address(this), new bytes(0));
    }

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
