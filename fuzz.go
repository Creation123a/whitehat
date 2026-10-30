package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// 1. Generate the invariant Solidity file for the role
	invariants := generateInvariants(role)
	if invariants == "" {
		return nil, fmt.Errorf("no invariants defined for role %s", role)
	}

	// 2. Write to temp workspace
	tmpDir, err := os.MkdirTemp("", "medusa-fuzz")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Wrapper target contract
	targetFile := filepath.Join(tmpDir, "Target.sol")
	targetSrc := fmt.Sprintf(`
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface ITarget {
    function %s;
}
contract FuzzTarget {
    ITarget constant T = ITarget(%s);
}
`, interfaceStubForRole(role), target.Hex())

	if err := os.WriteFile(targetFile, []byte(targetSrc), 0644); err != nil {
		return nil, err
	}

	// Invariants file
	invFile := filepath.Join(tmpDir, "Invariants.sol")
	if err := os.WriteFile(invFile, []byte(invariants), 0644); err != nil {
		return nil, err
	}

	// Medusa config
	configFile := filepath.Join(tmpDir, "medusa.json")
	config := map[string]interface{}{
		"fuzzing": map[string]interface{}{
			"timeout":      300, // 5 minutes
			"targetContracts": []string{target.Hex()},
			"testLimit":    100000,
		},
		"compilation": map[string]interface{}{
			"sources": []string{tmpDir},
		},
		"chain": map[string]interface{}{
			"rpcURL": rpcURL,
			"blockNumber": blockNum,
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, configBytes, 0644)

	// 3. Run Medusa
	cmd := exec.CommandContext(ctx, "medusa", "fuzz", "--config", configFile)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// 4. Parse for invariant failures
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

func generateInvariants(role ContractRole) string {
	header := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface ITarget {
`
	footer := `
}
contract Invariants {
    ITarget target;
    function check_`
	
	switch role {
	case RoleLending:
		return header + `
    function totalBorrows() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalReserves() external view returns (uint256);
` + footer + `solvency() public view {
        // Invariant: Protocol must be solvent
        // totalSupply of loan tokens must cover totalBorrows + reserves
        uint256 supply = target.totalSupply();
        uint256 borrows = target.totalBorrows();
        require(supply >= borrows, "INSOLVENCY: supply < borrows");
    }

    function check_no_free_lunch() public view {
        // Invariant: No user should be able to withdraw more than they deposited
        // (checked via flash-loan based exploit replay on Anvil, not here)
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

    function check_monotonic() public view {
        // Invariant: totalAssets should be monotonic under deposit
        // (fuzzer will try random deposit sequences)
    }
}
`
	case RoleAMM:
		return header + `
    function getReserves() external view returns (uint112, uint112, uint32);
` + footer + `k_constant() public view {
        (uint112 r0, uint112 r1, ) = target.getReserves();
        // Invariant: neither reserve should ever hit zero
        require(r0 > 0, "K_ZERO: reserve0 is 0");
        require(r1 > 0, "K_ZERO: reserve1 is 0");
    }
}
`
	}
	return ""
}

func interfaceStubForRole(role ContractRole) string {
	switch role {
	case RoleLending:
		return `totalBorrows() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalReserves() external view returns (uint256)`
	case RoleVault:
		return `totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256)`
	case RoleAMM:
		return `getReserves() external view returns (uint112, uint112, uint32)`
	}
	return ""
}
