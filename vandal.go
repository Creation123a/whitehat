package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/ethereum/go-ethereum/common"
)

// RunVandal executes Vandal on the raw bytecode.
func RunVandal(ctx context.Context, contractAddr string, bytecode []byte) (string, error) {
	log.Printf("scanner[static]: Running Vandal bytecode analysis on %s...", contractAddr)
	
	// 1. Write bytecode as a hex string to a temp file (Vandal expects hex, not raw binary)
	tmpFile, err := os.CreateTemp("", "vandal-bytecode-*.hex")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())
	
	// Convert to hex string (without the 0x prefix)
	hexStr := common.Bytes2Hex(bytecode)
	if _, err := tmpFile.WriteString(hexStr); err != nil {
		tmpFile.Close()
		return "", err
	}
	tmpFile.Close()

	// 2. Run Vandal on the bytecode file
	cmd := exec.CommandContext(ctx, "vandal", "analyze", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("scanner[static]: Vandal execution failed: %v\nOutput: %s", err, string(out))
		return "", fmt.Errorf("vandal execution failed: %w", err)
	}

	log.Printf("scanner[static]: Vandal completed. Parsing output...")
	
	// If Vandal found nothing, it might output a default string
	outputStr := string(out)
	if outputStr == "" || len(outputStr) < 10 {
		return "Vandal found no obvious bytecode vulnerabilities.", nil
	}
	
	return outputStr, nil
}
