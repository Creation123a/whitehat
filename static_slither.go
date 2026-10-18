package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type SlitherFinding struct {
	Check      string
	Impact     string
	Confidence string
	Description string
	Elements   []struct {
		Name string
		SourceMapping string
	}
}

type SlitherJSON struct {
	Success  bool             `json:"success"`
	Results  struct {
		Detectors []SlitherFinding `json:"detectors"`
	} `json:"results"`
}

// RunStaticAnalyzers runs Slither and Aderyn on the raw source code.
// It returns a summary string of high-impact findings to feed into the LLM prompt.
func RunStaticAnalyzers(sourceCode string, contractName string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "slither-audit")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// Write the source code to a .sol file
	solFile := filepath.Join(tmpDir, fmt.Sprintf("%s.sol", contractName))
	if err := os.WriteFile(solFile, []byte(sourceCode), 0644); err != nil {
		return "", err
	}

	// 1. Run Slither
	// Note: Slither might fail on missing imports (like OpenZeppelin) without a full project setup.
	cmd := exec.Command("slither", solFile, "--json", "-")
	out, _ := cmd.Output() // Ignore error as Slither returns non-zero on findings

	var slitherRes SlitherJSON
	_ = json.Unmarshal(out, &slitherRes)

	var summary string
	for _, finding := range slitherRes.Results.Detectors {
		if finding.Impact == "High" || finding.Impact == "Critical" {
			summary += fmt.Sprintf("- [SLITHER - %s] %s (Confidence: %s)\n", 
				finding.Check, finding.Description, finding.Confidence)
		}
	}

	// 2. Run Aderyn (Aderyn is a Rust-based Solidity AST scanner)
	// (Assuming Aderyn is installed globally in the runner as per the workflow)
	aderynCmd := exec.Command("aderyn", tmpDir, "--output", filepath.Join(tmpDir, "report.json"))
	_ = aderynCmd.Run() // Run silently

	// Read Aderyn report if it exists
	aderynReport, err := os.ReadFile(filepath.Join(tmpDir, "report.json"))
	if err == nil {
		var aderynRes struct {
			HighIssues []struct{ Title string; Description string }
			CriticalIssues []struct{ Title string; Description string }
		}
		if json.Unmarshal(aderynReport, &aderynRes) == nil {
			for _, i := range aderynRes.CriticalIssues {
				summary += fmt.Sprintf("- [ADERYN - CRITICAL] %s: %s\n", i.Title, i.Description)
			}
			for _, i := range aderynRes.HighIssues {
				summary += fmt.Sprintf("- [ADERYN - HIGH] %s: %s\n", i.Title, i.Description)
			}
		}
	}

	if summary == "" {
		return "No high/critical issues found by static analyzers.", nil
	}
	return summary, nil
}
