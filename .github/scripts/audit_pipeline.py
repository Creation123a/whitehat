import os
import glob
import json
import subprocess
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
MAX_CODE_CHARS = 60_000       # per-file code sent to LLM
MAX_REDUCE_CHARS = 100_000    # cap on combined per-file reports for reduce step

# Model IDs change frequently on both providers. Update if a model 404s.
PROVIDERS = [
    {
        "name": "OpenRouter Free",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "models": [
            "deepseek/deepseek-r1:free",
            "qwen/qwen-2.5-coder-32b-instruct:free",
            "meta-llama/llama-3.3-70b-instruct:free",
        ],
    },
    {
        "name": "Cerebras",
        "url": "https://api.cerebras.ai/v1/chat/completions",
        "key_env": "CEREBRAS_API_KEY",
        "models": [
            "qwen-3-32b",
            "llama-3.3-70b",
            "gpt-oss-120b",
        ],
    },
]


# ---------------------------------------------------------------------------
# LLM call with provider/model fallback
# ---------------------------------------------------------------------------
def call_llm(prompt: str, max_tokens: int = 3000) -> str:
    last_error = "no provider configured with an API key"
    for provider in PROVIDERS:
        api_key = os.environ.get(provider["key_env"], "").strip()
        if not api_key:
            continue

        for model in provider["models"]:
            payload = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
            }).encode("utf-8")

            req = urllib.request.Request(
                provider["url"],
                data=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Bridge-MapReduce-Auditor/1.1",
                },
            )

            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                choices = data.get("choices") or []
                if not choices:
                    last_error = f"{provider['name']}/{model}: empty choices"
                    continue

                content = (choices[0].get("message") or {}).get("content")
                # OpenAI-style "parts" content
                if isinstance(content, list):
                    content = "".join(
                        p.get("text", "") for p in content if isinstance(p, dict)
                    )
                content = (content or "").strip()
                if not content:
                    last_error = f"{provider['name']}/{model}: empty content"
                    continue

                time.sleep(3)  # be polite to free tiers
                return f"*Model: `{model}`*\n\n{content}"

            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", "ignore")[:200]
                except Exception:
                    pass
                last_error = f"{provider['name']}/{model}: HTTP {e.code} {body}"
                print(f"[WARN] {last_error} — trying next model...")
                time.sleep(2)
                continue
            except Exception as e:  # network, timeout, JSON, etc.
                last_error = f"{provider['name']}/{model}: {e!r}"
                print(f"[WARN] {last_error} — trying next model...")
                time.sleep(1)
                continue

    return f"**[ERROR]** All configured LLM endpoints failed. Last error: {last_error}"


# ---------------------------------------------------------------------------
# Comment stripping that (a) preserves line numbers and (b) ignores strings
# ---------------------------------------------------------------------------
def strip_comments(code: str) -> str:
    out = []
    i, n = 0, len(code)
    quote = None  # current string quote char, or None
    while i < n:
        c = code[i]

        if quote is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:          # escape
                out.append(code[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue

        if c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            continue

        if c == "/" and i + 1 < n:
            nxt = code[i + 1]
            if nxt == "/":                        # line comment
                j = code.find("\n", i)
                if j == -1:
                    break
                i = j                             # keep the newline
                continue
            if nxt == "*":                        # block comment
                j = code.find("*/", i + 2)
                if j == -1:
                    break
                # Preserve line count so LLM + Aderyn line numbers line up
                out.append("\n" * code[i:j + 2].count("\n"))
                i = j + 2
                continue

        out.append(c)
        i += 1

    return "".join(out)


# ---------------------------------------------------------------------------
# Aderyn (single run over project root)
# ---------------------------------------------------------------------------
def run_aderyn(root: str = ".") -> dict | None:
    output_json = "aderyn-report.json"
    if os.path.exists(output_json):
        os.remove(output_json)

    try:
        subprocess.run(
            ["aderyn", root, "-o", output_json],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        print("[WARN] `aderyn` binary not found on PATH.")
        return None

    if not os.path.exists(output_json):
        print("[WARN] Aderyn produced no output file (project build likely failed).")
        return None

    try:
        with open(output_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Could not parse Aderyn JSON: {e}")
        return None
    finally:
        try:
            os.remove(output_json)
        except OSError:
            pass

    return data


def _norm_path(p: str) -> str:
    p = (p or "").replace("\\", "/")
    if p:
        p = os.path.normpath(p)
    return p[2:] if p.startswith("./") else p


def _pick_block(data: dict, keys: tuple) -> object:
    for k in keys:
        if data.get(k):
            return data[k]
    return {}


def findings_for_file(aderyn_data: dict | None, filepath: str) -> list:
    if not aderyn_data:
        return []

    target = _norm_path(filepath)
    findings = []

    for sev_keys, sev_name in (
        (("high_issues", "high"), "High"),
        (("low_issues", "low"), "Low"),
    ):
        block = _pick_block(aderyn_data, sev_keys)
        if isinstance(block, dict):
            issues = block.get("issues") or []
        elif isinstance(block, list):
            issues = block
        else:
            issues = []

        for issue in issues:
            matched = []
            for inst in issue.get("instances", []):
                cpath = _norm_path(inst.get("contract_path", ""))
                if not cpath:
                    continue
                if (
                    cpath == target
                    or cpath.endswith("/" + target)
                    or target.endswith("/" + cpath)
                ):
                    matched.append(
                        f"Line {inst.get('line_no')}: {inst.get('src_char', '')}"
                    )
            if matched:
                findings.append({
                    "severity": sev_name,
                    "title": issue.get("title", ""),
                    "description": issue.get("description", ""),
                    "instances": matched,
                })

    return findings


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def discover_solidity_files() -> list[str]:
    excluded_dirs = {
        "node_modules", "lib", "test", "tests", "mock", "mocks",
        "script", "scripts", "out", "cache", "broadcast", "artifacts",
    }
    results = []
    for f in glob.glob("**/*.sol", recursive=True):
        if f.endswith((".t.sol", ".s.sol")):
            continue
        parts = _norm_path(f).split("/")[:-1]
        if any(p in excluded_dirs for p in parts):
            continue
        results.append(f)
    return sorted(results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    sol_files = discover_solidity_files()
    print(f"[INFO] Discovered {len(sol_files)} Solidity file(s) to audit.")

    if not sol_files:
        with open("final-audit-report.md", "w", encoding="utf-8") as f:
            f.write(
                "# Cross-Chain Bridge Security Audit Report\n\n"
                "No Solidity files found to audit.\n"
            )
        return

    print("[INFO] Running Aderyn on project root...")
    aderyn_data = run_aderyn(".")
    aderyn_ok = aderyn_data is not None

    per_file_reports = []

    for filepath in sol_files:
        print(f"[MAP] Auditing {filepath} ...")

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError as e:
            per_file_reports.append(
                f"## File: `{filepath}`\n\n**[ERROR]** Could not read file: {e}"
            )
            continue

        clean_code = strip_comments(raw)
        if len(clean_code) > MAX_CODE_CHARS:
            clean_code = (
                clean_code[:MAX_CODE_CHARS]
                + "\n// ...[TRUNCATED: file too large for LLM context]..."
            )

        if aderyn_ok:
            aderyn_findings = json.dumps(
                findings_for_file(aderyn_data, filepath), indent=2
            )
        else:
            aderyn_findings = (
                "Aderyn did not produce output (project build may have failed). "
                "Perform the audit from code review only."
            )

        file_prompt = f"""You are a senior smart contract security auditor specializing in cross-chain bridges, messaging adapters, message receivers, and wrapped token minters/escrows.
Audit the Solidity file below alongside its automated Aderyn static-analysis output.

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

        llm_response = call_llm(file_prompt, max_tokens=3000)
        per_file_reports.append(f"## File: `{filepath}`\n\n{llm_response}")

    combined_file_reports = "\n\n---\n\n".join(per_file_reports)
    if len(combined_file_reports) > MAX_REDUCE_CHARS:
        combined_file_reports = (
            combined_file_reports[:MAX_REDUCE_CHARS]
            + "\n\n...[TRUNCATED FOR REDUCE CONTEXT]..."
        )

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
    cross_file_report = call_llm(cross_file_prompt, max_tokens=5000)

    with open("final-audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Cross-Chain Bridge Security Audit Report\n\n")
        f.write("## Part 1: Cross-Contract & Cross-Chain Security Analysis\n\n")
        f.write(cross_file_report)
        f.write("\n\n---\n\n")
        f.write("## Part 2: Individual File Audits\n\n")
        f.write(combined_file_reports)

    print("[INFO] Audit complete. Output written to final-audit-report.md")


if __name__ == "__main__":
    main()
