package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// DecompileWithHeimdall runs the Heimdall-rs binary to decompile a contract's
// bytecode into pseudo-Solidity if the source is unverified.
func DecompileWithHeimdall(ctx context.Context, address string, rpcURL string) (string, error) {
	// 1. Create a temporary directory to hold the decompiled output
	tmpDir, err := os.MkdirTemp("", "heimdall-output")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	// Clean up the directory when the function returns
	defer os.RemoveAll(tmpDir)

	log.Printf("scanner[heimdall]: Decompiling unverified contract %s... (This may take a few seconds)", address)

	// 2. Enforce a strict 120-second timeout specifically for Heimdall
	// This prevents a single massive contract from stalling the entire pipeline.
	heimdallCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// 3. Build the Heimdall command
	// -r: RPC URL to fetch bytecode
	// --include-sol: Output pseudo-Solidity code
	// --skip-resolving: Skip online 4byte database lookups (much faster)
	// -o: Output directory
	cmd := exec.CommandContext(heimdallCtx, "heimdall", "decompile", address, "-r", rpcURL, "--include-sol", "--skip-resolving", "-o", tmpDir)

	// 4. Execute and capture both stdout and stderr for comprehensive logging
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the error was specifically caused by our 120s timeout
		if heimdallCtx.Err() == context.DeadlineExceeded {
			log.Printf("scanner[heimdall]: Execution timed out after 120s for %s", address)
			return "", fmt.Errorf("decompile_timeout")
		}
		
		log.Printf("scanner[heimdall]: Execution failed: %v\nRaw Output: %s", err, string(output))
		return "", fmt.Errorf("heimdall decompile failed: %w", err)
	}

	log.Printf("scanner[heimdall]: Decompilation engine finished. Parsing output...")

	// 5. Locate the generated decompiled.sol file
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

	log.Printf("scanner[heimdall]: Successfully generated %d bytes of pseudo-Solidity.", len(solBytes))
	return string(solBytes), nil
}
