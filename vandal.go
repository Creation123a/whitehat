package main

import (
	"context"
	"log"
	"os"
	"os/exec"
)

// RunVandal executes Vandal on the raw bytecode.
func RunVandal(ctx context.Context, contractAddr string, bytecode []byte) (string, error) {
	log.Printf("scanner[static]: Running Vandal bytecode analysis on %s...", contractAddr)
	
	// 1. Write bytecode to a temp file
	tmpFile, err := os.CreateTemp("", "vandal-bytecode-*.bin")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())
	
	if _, err := tmpFile.Write(bytecode); err != nil {
		tmpFile.Close()
		return "", err
	}
	tmpFile.Close()

	// 2. Run Vandal on the bytecode file
	cmd := exec.CommandContext(ctx, "vandal", "analyze", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("scanner[static]: Vandal execution failed: %v\nOutput: %s", err, string(out))
		return "", err
	}

	log.Printf("scanner[static]: Vandal completed. Parsing output...")
	return string(out), nil
}
