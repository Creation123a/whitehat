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

	// We only write Invariants.sol. It contains the interface and the target initialization.
	invFile := filepath.Join(tmpDir, "Invariants.sol")
	if err := os.WriteFile(invFile, []byte(invariants), 0644); err != nil {
		return nil, err
	}

	// 3. Medusa config
	configFile := filepath.Join(tmpDir, "medusa.json")
	config := map[string]interface{}{
		"fuzzing": map[string]interface{}{
			"timeout":         300, // 5 minutes
			"targetContracts": []string{"Invariants"}, // Fuzz the Invariants contract
			"testLimit":       100000,
		},
		"compilation": map[string]interface{}{
			"sources": []string{tmpDir},
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
	if strings.Contains(outStr, "assertion failed") || strings.Contains(outStr, "Failed!") {
		result.InvariantBroken = true
		for _, line := range strings.Split(outStr, "\n") {
			if strings.Contains(line, "assertion") || strings.Contains(line, "invariant") {
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
    function check_`, target.Hex())

	switch role {
	case RoleLending:
		return header + `
    function totalBorrows() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalReserves() external view returns (uint256);
` + footer + `solvency() public view {
        // Invariant: Protocol must be solvent
        uint256 supply = target.totalSupply();
        uint256 borrows = target.totalBorrows();
        require(supply >= borrows, "INSOLVENCY: supply < borrows");
    }
}
`
	case RoleVault:
		return header + `
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
` + footer + `share_math() public view {
        // Invariant: 1 share should never be worth more than total assets
        uint256 assets = target.totalAssets();
        uint256 supply = target.totalSupply();
        if (supply == 0) {
            require(assets == 0, "INFLATION: assets exist with 0 shares");
        }
    }
}
`
	case RoleAMM:
		return header + `
    function getReserves() external view returns (uint112, uint112, uint32);
` + footer + `k_constant() public view {
        // Invariant: neither reserve should ever hit zero
        (uint112 r0, uint112 r1, ) = target.getReserves();
        require(r0 > 0, "K_ZERO: reserve0 is 0");
        require(r1 > 0, "K_ZERO: reserve1 is 0");
    }
}
`
	}
	return ""
}
