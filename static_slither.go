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
	tmpDir, err := os.MkdirTemp("", "foundry-audit")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	// 1. Initialize a dummy Foundry project
	cmdInit := exec.Command("forge", "init", "--force")
	cmdInit.Dir = tmpDir
	_ = cmdInit.Run()

	// 2. Write the target contract to src/
	solFile := filepath.Join(tmpDir, "src", fmt.Sprintf("%s.sol", contractName))
	_ = os.WriteFile(solFile, []byte(sourceCode), 0644)

	// 3. Run Slither inside the project
	cmd := exec.Command("slither", ".", "--json", "-")
	cmd.Dir = tmpDir
	out, _ := cmd.Output()

	var slitherRes SlitherJSON
	_ = json.Unmarshal(out, &slitherRes)

	var summary string
	for _, finding := range slitherRes.Results.Detectors {
		if finding.Impact == "High" || finding.Impact == "Critical" {
			summary += fmt.Sprintf("- [SLITHER - %s] %s (Confidence: %s)\n", 
				finding.Check, finding.Description, finding.Confidence)
		}
	}

	// 4. Run Aderyn
	aderynCmd := exec.Command("aderyn", ".", "--output", "report.json")
	aderynCmd.Dir = tmpDir
	_ = aderynCmd.Run()

		// Inside RunStaticAnalyzers function:
	aderynReport, err := os.ReadFile(filepath.Join(tmpDir, "report.json"))
	if err == nil {
		var aderynRes struct {
			HighIssues struct {
				Issues []struct {
					Title       string `json:"title"`
					Description string `json:"description"`
				} `json:"issues"`
			} `json:"high_issues"`
			CriticalIssues struct {
				Issues []struct {
					Title       string `json:"title"`
					Description string `json:"description"`
				} `json:"issues"`
			} `json:"critical_issues"`
		}
		if json.Unmarshal(aderynReport, &aderynRes) == nil {
			for _, i := range aderynRes.CriticalIssues.Issues {
				summary += fmt.Sprintf("- [ADERYN - CRITICAL] %s: %s\n", i.Title, i.Description)
			}
			for _, i := range aderynRes.HighIssues.Issues {
				summary += fmt.Sprintf("- [ADERYN - HIGH] %s: %s\n", i.Title, i.Description)
			}
		}
	}

	if summary == "" {
		return "No high/critical issues found by static analyzers.", nil
	}
	return summary, nil
}
