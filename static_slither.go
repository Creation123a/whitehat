package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
)

// RunVandal executes Vandal on the raw bytecode via RPC.
func RunVandal(ctx context.Context, contractAddr string, rpcURL string) (string, error) {
	log.Printf("scanner[static]: Running Vandal bytecode analysis on %s...", contractAddr)
	
	// Vandal command to analyze bytecode from an address
	cmd := exec.CommandContext(ctx, "vandal", "analyze", contractAddr, "--rpc", rpcURL)
	out, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("scanner[static]: Vandal execution failed: %v\nOutput: %s", err, string(out))
		return "", err
	}

	log.Printf("scanner[static]: Vandal completed. Parsing output...")
	return string(out), nil
}
