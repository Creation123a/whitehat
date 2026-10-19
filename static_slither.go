// static_slither.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SlitherFinding struct {
	Check       string `json:"check"`
	Impact      string `json:"impact"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	Elements    []struct {
		Name          string `json:"name"`
		SourceMapping string `json:"source_mapping"`
	} `json:"elements"`
}

type SlitherJSON struct {
	Success bool `json:"success"`
	Results struct {
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

	log.Printf("scanner[static]: Initializing Foundry project for %s", contractName)

	// 1. Initialize a dummy Foundry project
	cmdInit := exec.Command("forge", "init", "--force")
	cmdInit.Dir = tmpDir
	if out, err := cmdInit.CombinedOutput(); err != nil {
		log.Printf("scanner[static]: Foundry init failed: %v\nOutput: %s", err, string(out))
		return "", err
	}

	// 2. Write the target contract to src/
	solFile := filepath.Join(tmpDir, "src", fmt.Sprintf("%s.sol", contractName))
	if err := os.WriteFile(solFile, []byte(sourceCode), 0644); err != nil {
		log.Printf("scanner[static]: Failed to write source file: %v", err)
		return "", err
	}

	// 3. Run Slither inside the project
	log.Printf("scanner[static]: Running Slither on %s...", contractName)
	cmd := exec.Command("slither", ".", "--json", "-")
	cmd.Dir = tmpDir
	
	// Using CombinedOutput to catch compilation errors
	out, err := cmd.CombinedOutput()
	
	var summary strings.Builder
	slitherCount := 0

	// Slither returns exit code 255 if it finds issues, so we check the output instead of the error
	if len(out) > 0 {
		var slitherRes SlitherJSON
		// Attempt to extract JSON if there's compilation noise
		jsonStart := strings.Index(string(out), "{")
		if jsonStart >= 0 {
			if err := json.Unmarshal(out[jsonStart:], &slitherRes); err == nil {
				for _, finding := range slitherRes.Results.Detectors {
					if finding.Impact == "High" || finding.Impact == "Critical" {
						slitherCount++
						log.Printf("scanner[static]: SLITHER FLAG [%s] %s", finding.Impact, finding.Check)
						summary.WriteString(fmt.Sprintf("- [SLITHER - %s] %s (Confidence: %s)\n", 
							finding.Check, finding.Description, finding.Confidence))
					}
				}
			} else {
				log.Printf("scanner[static]: Slither JSON parse failed. Raw output: %s", string(out))
			}
		} else if err != nil {
			// Compilation failure usually happens here
			log.Printf("scanner[static]: Slither compilation failed. Output: %s", string(out))
		}
	}

	if slitherCount == 0 {
		log.Printf("scanner[static]: Slither found 0 High/Critical issues.")
	}

	// 4. Run Aderyn
	log.Printf("scanner[static]: Running Aderyn on %s...", contractName)
	aderynCmd := exec.Command("aderyn", ".", "--output", "report.json")
	aderynCmd.Dir = tmpDir
	if out, err := aderynCmd.CombinedOutput(); err != nil {
		log.Printf("scanner[static]: Aderyn execution failed: %v\nOutput: %s", err, string(out))
	}

	aderynCount := 0
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
				aderynCount++
				log.Printf("scanner[static]: ADERYN FLAG [CRITICAL] %s", i.Title)
				summary.WriteString(fmt.Sprintf("- [ADERYN - CRITICAL] %s: %s\n", i.Title, i.Description))
			}
			for _, i := range aderynRes.HighIssues.Issues {
				aderynCount++
				log.Printf("scanner[static]: ADERYN FLAG [HIGH] %s", i.Title)
				summary.WriteString(fmt.Sprintf("- [ADERYN - HIGH] %s: %s\n", i.Title, i.Description))
			}
		}
	}
	
	if aderynCount == 0 {
		log.Printf("scanner[static]: Aderyn found 0 High/Critical issues.")
	}

	if summary.Len() == 0 {
		return "No high/critical issues found by static analyzers.", nil
	}
	
	log.Printf("scanner[static]: Total static findings: %d", slitherCount+aderynCount)
	return summary.String(), nil
}
