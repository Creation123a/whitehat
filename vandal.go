package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// RunVandal executes Mythril on the raw bytecode.
// The function name is kept as RunVandal to maintain compatibility with main.go.
func RunVandal(ctx context.Context, contractAddr string, bytecode []byte) (string, error) {
	log.Printf("scanner[static]: Running bytecode analysis (Mythril) on %s...", contractAddr)
	
	// 1. Create a temp file for the raw runtime bytecode
	tmpFile, err := os.CreateTemp("", "mythril-bytecode-*.bin")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	
	// Write the raw bytecode to the file
	if _, err := tmpFile.Write(bytecode); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to write bytecode: %w", err)
	}
	tmpFile.Close()

	// 2. Run Mythril on the bytecode file
	// -t 2: Limit transaction depth to 2 to control path explosion.
	// --execution-timeout 300: Give Mythril 5 minutes for a meaningful analysis.
	cmd := exec.CommandContext(ctx, "myth", "analyze", "--bin-runtime", tmpFile.Name(), "-t", "2", "--execution-timeout", "300")
	out, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("scanner[static]: Mythril execution failed or timed out: %v\nOutput: %s", err, string(out))
		return "Mythril analysis failed or timed out.", nil
	}

	log.Printf("scanner[static]: Mythril completed. Parsing output...")
	
	outputStr := string(out)
	if outputStr == "" || len(outputStr) < 10 {
		return "Mythril found no obvious bytecode vulnerabilities.", nil
	}
	
	return outputStr, nil
}
