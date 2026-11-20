import os
import re
import glob
import json
import subprocess
import time
import urllib.request
import urllib.error

PROVIDERS = [
    {
        "name": "OpenRouter Free",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "models": [
            "openrouter/free",
            "deepseek/deepseek-v4.1-flash",
            "nvidia/nemotron-3.5-lightning:free",
            "qwen/qwen-2.5-coder-32b-instruct:free"
        ]
    },
    {
        "name": "Cerebras Free",
        "url": "https://cerebras.ai",
        "key_env": "CEREBRAS_API_KEY",
        "models": [
            "qwen-3.8-27b",
            "gpt-oss-120b"
        ]
    }
]


def call_llm(prompt: str) -> str:
    for provider in PROVIDERS:
        api_key = os.environ.get(provider["key_env"], "").strip()
        if not api_key:
            continue

        for model in provider["models"]:
            payload = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            }).encode("utf-8")

            req = urllib.request.Request(
                provider["url"],
                data=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Bridge-MapReduce-Auditor/1.0"
                }
            )

            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data["choices"]["message"]["content"]
                    time.sleep(4)
                    return f"*Model: `{model}`*\n\n{content}"

            except urllib.error.HTTPError as e:
                if e.code in (400, 404, 413, 429, 502, 503):
                    print(f"[WARN] {provider['name']} ({model}) returned HTTP {e.code}. Trying next...")
                    time.sleep(2)
                    continue
                raise

    return "**[ERROR]** All configured free LLM endpoints hit rate limits or lacked API keys."


def strip_comments(code: str) -> str:
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    code = re.sub(r'//.*', '', code)
    return "\n".join(line for line in code.splitlines() if line.strip())


def run_aderyn_on_file(filepath: str) -> str:
    output_json = "aderyn-single.json"
    if os.path.exists(output_json):
        os.remove(output_json)

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
    all_sol = glob.glob("**/*.sol", recursive=True)
    excluded_dirs = ("node_modules/", "lib/", "test/", "tests/", "mock/", "mocks/", "script/", "scripts/")
    filtered = [
        f for f in all_sol
        if not f.startswith(excluded_dirs)
        and not any(f"/{d}" in f for d in excluded_dirs)
        and not f.endswith((".t.sol", ".s.sol"))
    ]
    return sorted(filtered)


def main():
    sol_files = discover_solidity_files()

    if not sol_files:
        with open("final-audit-report.md", "w", encoding="utf-8") as f:
            f.write("# Cross-Chain Bridge Security Audit Report\n\nNo Solidity files found to audit.\n")
        return

    per_file_reports = []

    for filepath in sol_files:
        print(f"[MAP] Running Aderyn & LLM audit on: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            clean_code = strip_comments(f.read())

        aderyn_findings = run_aderyn_on_file(filepath)

        file_prompt = f"""You are a senior smart contract security auditor specializing in cross-chain bridges, messaging adapters, message receivers, and wrapped token minters/escrows.
Audit the Solidity file below alongside its automated Aderyn static analysis output.

Respond strictly in two concise sections:
### 1. Short File Summary
- Identify the contract's role (Adapter, Receiver, Wrapped Token Minter/Burner, Escrow, or Router), trust assumptions (relayer/endpoint/sequencer), key state variables, external/public entrypoints, and cross-chain/external calls (under 130 words).

### 2. File Vulnerabilities
- Validate Aderyn's findings (confirm True Positives, dismiss False Positives).
- Identify any High or Medium bridge-specific or general logic bugs:
  * Missing source chain ID, source sender/adapter, or endpoint authentication
  * Replay attacks, missing/broken nonce enforcement, or out-of-order execution flaws
  * Unauthorized minting/burning, supply accounting mismatch, or fee-on-transfer/rebasing token issues
  * Payload decoding/encoding malleability, gas-limit griefing, or stuck failed messages
  * Reentrancy, access control, and decimal/rounding errors
- Provide concise remediation steps for confirmed issues.

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

    print("[REDUCE] Running cross-file bridge vulnerability analysis...")

    cross_file_prompt = f"""You are a Lead Cross-Chain Security Auditor conducting an end-to-end architectural review across bridge adapters, message receivers, and wrapped token minters.
Below are the individual audit summaries and findings for every file in the codebase.

Using ONLY these summaries, identify **Cross-Contract & Cross-Chain Vulnerabilities**:
1. Adapter <-> Receiver Trust & Encoding Mismatches: Differences in payload ABI encoding/decoding, chain ID mappings, peer/trusted remote registration, or relayer verification between sending adapters and receiving endpoints.
2. Lock/Burn <-> Mint/Unlock Accounting Desynchronization: Scenarios where tokens are minted without corresponding lock/burn, double-minted via replay, or permanently locked if a cross-chain message reverts on the destination chain.
3. Cross-Contract & Read-Only Reentrancy: Callbacks during token mint/transfer or bridge hooks that corrupt shared bridge state or accounting.
4. Privilege Escalation & Admin/Guardian Key Risks: Mismatched roles (`MINTER_ROLE`, `ADAPTER_ROLE`, `ENDPOINT`) allowing unauthorized minting or message spoofing across contracts.

Format the output as:
### Executive Summary
### Cross-Contract & Cross-Chain Vulnerabilities (High / Medium)
### Prioritized Remediation Checklist

Per-File Audit Summaries:
{combined_file_reports}
"""
    cross_file_report = call_llm(cross_file_prompt)

    with open("final-audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Cross-Chain Bridge Security Audit Report\n\n")
        f.write("## Part 1: Cross-Contract & Cross-Chain Security Analysis\n\n")
        f.write(cross_file_report)
        f.write("\n\n---\n\n")
        f.write("## Part 2: Individual File Audits\n\n")
        f.write(combined_file_reports)

    print("Audit complete. Output written to final-audit-report.md")


if __name__ == "__main__":
    main()
```
