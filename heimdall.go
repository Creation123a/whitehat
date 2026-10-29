package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// decompileCache keys decompiled source by keccak256(bytecode) so identical
// implementations (e.g. multiple proxies pointing to the same logic) only
// decompile once.
var decompileCache = make(map[common.Hash]string)

// protocolDecompileCounts tracks how many decompiles have been run for a
// specific protocol slug during this scan run.
var protocolDecompileCounts = make(map[string]int)

// CanDecompile checks if the protocol has reached the max decompile limit.
func CanDecompile(protocolSlug string) bool {
	return protocolDecompileCounts[protocolSlug] < maxDecompilesPerProtocol
}

// IncrementDecompileCount increments the decompile counter for a protocol.
func IncrementDecompileCount(protocolSlug string) {
	protocolDecompileCounts[protocolSlug]++
}

// DecompileWithHeimdall runs the Heimdall-rs binary to decompile a contract's
// bytecode into pseudo-Solidity.
//
// v11.0 Changes:
//   - Gated: Only runs if provenVuln or structuralTaint is true.
//   - Cached: Keyed by keccak256(bytecode).
//   - Limited: Enforces maxDecompilesPerProtocol.
func DecompileWithHeimdall(
	ctx context.Context,
	protocolSlug string,
	address string,
	bytecode []byte,
	rpcURL string,
	provenVuln bool,
	structuralTaint bool,
) (string, error) {

	// 1. Gating Check: Do not decompile if there is no proof or structural taint.
	if !provenVuln && !structuralTaint {
		return "", fmt.Errorf("skipped: no proof and no structural taint")
	}

	// 2. Limit Check: Enforce maxDecompilesPerProtocol.
	if !CanDecompile(protocolSlug) {
		log.Printf("scanner[heimdall]: Max decompiles (%d) reached for protocol %s", maxDecompilesPerProtocol, protocolSlug)
		return "", fmt.Errorf("max_decompiles_reached")
	}

	// 3. Cache Check: Key by keccak256(bytecode)
	hash := crypto.Keccak256Hash(bytecode)
	if cached, ok := decompileCache[hash]; ok {
		log.Printf("scanner[heimdall]: Cache hit for %s (hash %s)", address, hash.Hex())
		return cached, nil
	}

	// 4. Create a temporary directory to hold the decompiled output
	tmpDir, err := os.MkdirTemp("", "heimdall-output")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Printf("scanner[heimdall]: Decompiling contract %s... (This may take a few seconds)", address)

	// 5. Enforce a strict 120-second timeout specifically for Heimdall
	heimdallCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// 6. Build the Heimdall command using --code to avoid redundant RPC calls.
	// Since we already fetched the bytecode in scanTarget, we can pass it directly.
	hexCode := common.Bytes2Hex(bytecode)
	cmd := exec.CommandContext(heimdallCtx, "heimdall", "decompile", "--code", hexCode, "--include-sol", "--skip-resolving", "-o", tmpDir)

	// 7. Execute and capture both stdout and stderr for comprehensive logging
	output, err := cmd.CombinedOutput()
	if err != nil {
		if heimdallCtx.Err() == context.DeadlineExceeded {
			log.Printf("scanner[heimdall]: Execution timed out after 120s for %s", address)
			return "", fmt.Errorf("decompile_timeout")
		}
		log.Printf("scanner[heimdall]: Execution failed: %v\nRaw Output: %s", err, string(output))
		return "", fmt.Errorf("heimdall decompile failed: %w", err)
	}

	log.Printf("scanner[heimdall]: Decompilation engine finished. Parsing output...")

	// 8. Locate the generated decompiled.sol file
	solPath := filepath.Join(tmpDir, "decompiled.sol")
	solBytes, err := os.ReadFile(solPath)

	// Fallback: If the file name changed or is nested, search for any .sol file
	if err != nil {
		files, _ := filepath.Glob(filepath.Join(tmpDir, "*.sol"))
		if len(files) > 0 {
			solPath = files[0]
			solBytes, err = os.ReadFile(solPath)
		}
	}

	if err != nil {
		log.Printf("scanner[heimdall]: Failed to find decompiled output in %s", tmpDir)
		return "", fmt.Errorf("failed to read decompiled.sol: %w", err)
	}

	// 9. Increment count, cache the result, and return
	IncrementDecompileCount(protocolSlug)
	result := string(solBytes)
	decompileCache[hash] = result

	log.Printf("scanner[heimdall]: Successfully generated %d bytes of pseudo-Solidity for %s.", len(result), address)
	return result, nil
}
