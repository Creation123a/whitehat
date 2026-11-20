import os
import re
import glob
import json
import subprocess


# =========================================================
# TODO: Implement your LLM API call here
# =========================================================
def call_llm(prompt: str) -> str:
    """
    TODO: Connect your preferred LLM API endpoint here (OpenRouter, GitHub Models, Gemini, etc.).
    Must accept `prompt` (str) and return the model's response text (str).
    """
    raise NotImplementedError("TODO: Implement LLM API call in call_llm()")


# =========================================================
# Helpers
# =========================================================
def strip_comments(code: str) -> str:
    """Removes comments and blank lines to reduce token consumption."""
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    code = re.sub(r'//.*', '', code)
    return "\n".join(line for line in code.splitlines() if line.strip())


def run_aderyn_on_file(filepath: str) -> str:
    """Runs Aderyn scoped to a single Solidity file and extracts findings."""
    output_json = "aderyn-single.json"
    if os.path.exists(output_json):
        os.remove(output_json)

    # -i scopes Aderyn to the specific file; -o writes JSON output
    subprocess.run(
        ["aderyn", "-i", filepath, "-o", output_json],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )

    if not os.path.exists(output_json):
        return "No Aderyn findings (or file skipped)."

    with open(output_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    os.remove(output_json)

    findings = []
    for severity in ["high_issues", "low_issues"]:
        issues = data.get(severity, {}).get("issues", [])
        for issue in issues:
            findings.append({
                "severity": "High" if severity == "high_issues" else "Low",
                "title": issue.get("title", ""),
                "description": issue.get("description", ""),
                "instances": [
                    f"Line {inst.get('line_no')}: {inst.get('src_char', '')}"
                    for inst in issue.get("instances", [])
                ]
            })

    return json.dumps(findings, indent=2) if findings else "No issues flagged by Aderyn."


def discover_solidity_files() -> list[str]:
    """Finds all relevant .sol files while excluding tests, mocks, and dependencies."""
    all_sol = glob.glob("**/*.sol", recursive=True)
    excluded_dirs = ("node_modules/", "lib/", "test/", "tests/", "mock/", "mocks/", "script/", "scripts/")
    filtered = [
        f for f in all_sol
        if not f.startswith(excluded_dirs)
        and not any(f"/{d}" in f for d in excluded_dirs)
        and not f.endswith((".t.sol", ".s.sol"))
    ]
    return sorted(filtered)


# =========================================================
# Main Map-Reduce Pipeline
# =========================================================
def main():
    sol_files = discover_solidity_files()

    if not sol_files:
        with open("final-audit-report.md", "w", encoding="utf-8") as f:
            f.write("# Security Audit Report\n\nNo Solidity files found to audit.\n")
        return

    per_file_reports = []

    # PHASE 1 (MAP): Audit 1 file + its Aderyn output at a time
    for filepath in sol_files:
        print(f"[MAP] Running Aderyn & LLM audit on: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            clean_code = strip_comments(f.read())

        aderyn_findings = run_aderyn_on_file(filepath)

        file_prompt = f"""You are a senior smart contract security auditor.
Audit the Solidity file below alongside its automated Aderyn static analysis output.

Respond strictly in two concise sections:
### 1. Short File Summary
- Describe the contract's purpose, key state variables, external/public entrypoints, and external contract calls (under 120 words).

### 2. File Vulnerabilities
- Validate Aderyn's findings (confirm True Positives, dismiss False Positives).
- Identify any High or Medium logic bugs (reentrancy, access control, math/rounding, oracle/flash-loan manipulation) with concise remediation steps.

File: `{filepath}`

Aderyn Output:
```json
{aderyn_findings}
```

Solidity Code:
```solidity
{clean_code}
```"""
        llm_response = call_llm(file_prompt)
        per_file_reports.append(f"## File: `{filepath}`\n\n{llm_response}")

    combined_file_reports = "\n\n---\n\n".join(per_file_reports)

    # PHASE 2 (REDUCE): Feed ONLY the per-file summaries/bugs for cross-file analysis
    print("[REDUCE] Running cross-file vulnerability analysis...")

    cross_file_prompt = f"""You are a Lead Smart Contract Auditor conducting a cross-contract security review.
Below are the individual audit summaries and findings for every file in the codebase.

Using ONLY these summaries, identify **Cross-Contract & System-Level Vulnerabilities**:
1. Cross-contract or read-only reentrancy.
2. State desynchronization or broken accounting invariants across contracts.
3. Privilege escalation or mismatched access control between interacting contracts.
4. Multi-contract flash-loan or price manipulation paths.

Format the output as:
### Executive Summary
### Cross-Contract Vulnerabilities (High / Medium)
### Prioritized Remediation Checklist

Per-File Audit Summaries:
{combined_file_reports}
"""
    cross_file_report = call_llm(cross_file_prompt)

    # Write final combined report for GitHub Artifact download
    with open("final-audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Smart Contract Security Audit Report\n\n")
        f.write("## Part 1: Cross-Contract Security Analysis\n\n")
        f.write(cross_file_report)
        f.write("\n\n---\n\n")
        f.write("## Part 2: Individual File Audits\n\n")
        f.write(combined_file_reports)

    print("Audit complete. Output written to final-audit-report.md")


if __name__ == "__main__":
    main()
```
