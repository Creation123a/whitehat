import os
import glob
import json
import subprocess
import time
import urllib.request
import urllib.error
import threading
import socket

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
MAX_CODE_CHARS = 60_000             # per-file code sent to LLM
MAX_REDUCE_BATCH_CHARS = 150_000    # safety cap per reduce batch input

# Time budgets (wall-clock, from start of main())
MAP_BUDGET_SECONDS = 40 * 60        # stop starting new files after 40 min
REDUCE_BUDGET_SECONDS = 8 * 60      # stop reduce phase after 8 more min

# ---------------------------------------------------------------------------
# Rate limiter for NVIDIA NIM: < 40 RPM => 1.6s min gap (37.5 RPM)
# ---------------------------------------------------------------------------
_nvidia_lock = threading.Lock()
_nvidia_last_call = 0.0
NVIDIA_MIN_INTERVAL = 1.6


def _nvidia_wait() -> None:
    """Block until NVIDIA_MIN_INTERVAL has elapsed since the last NIM call."""
    global _nvidia_last_call
    with _nvidia_lock:
        now = time.time()
        gap = now - _nvidia_last_call
        if gap < NVIDIA_MIN_INTERVAL:
            time.sleep(NVIDIA_MIN_INTERVAL - gap)
        _nvidia_last_call = time.time()


PROVIDERS = [
    {
        "name": "NVIDIA NIM",
        "url": "https://integrate.api.nvidia.com/v1/chat/completions",
        "key_env": "NVIDIA_API_KEY",
        "rate_limit_fn": _nvidia_wait,
        "max_retries_per_model": 2,
        "backoff_seconds": 2.0,
        "models": [
            "moonshotai/kimi-k3.1-pro",       # primary
            "minimaxai/minimax-m3.1-flash",   # fallback
        ],
        "model_options": {
            "moonshotai/kimi-k3.1-pro":     {"reasoning_effort": "low"},
            "minimaxai/minimax-m3.1-flash": {"top_p": 0.95},
        },
    },
    {
        "name": "OpenRouter Free",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "models": [
            "nvidia/nemotron-3-ultra-550b-a55b:free",
            "baidu/ernie-5.5-flash-preview:free",
            "stepfun/step-3.5-flash:free",
            "cohere/north-mini-code:free",
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

        rl_fn = provider.get("rate_limit_fn")
        max_retries = provider.get("max_retries_per_model", 1)
        backoff = provider.get("backoff_seconds", 2.0)
        model_opts = provider.get("model_options", {})

        for model in provider["models"]:
            payload_obj = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": max_tokens,
            }
            payload_obj.update(model_opts.get(model, {}))
            payload = json.dumps(payload_obj).encode("utf-8")

            req_headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Bridge-MapReduce-Auditor/1.3",
            }

            for attempt in range(1, max_retries + 1):
                if rl_fn:
                    rl_fn()

                req = urllib.request.Request(
                    provider["url"], data=payload, headers=req_headers
                )

                try:
                    with urllib.request.urlopen(req, timeout=90) as resp:
                        data = json.loads(resp.read().decode("utf-8"))

                    choices = data.get("choices") or []
                    if not choices:
                        last_error = f"{provider['name']}/{model}: empty choices"
                        break

                    content = (choices[0].get("message") or {}).get("content")
                    if isinstance(content, list):
                        content = "".join(
                            p.get("text", "") for p in content if isinstance(p, dict)
                        )
                    content = (content or "").strip()
                    if not content:
                        last_error = f"{provider['name']}/{model}: empty content"
                        break

                    return f"*Model: `{model}`*\n\n{content}"

                except urllib.error.HTTPError as e:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", "ignore")[:200]
                    except Exception:
                        pass
                    last_error = f"{provider['name']}/{model}: HTTP {e.code} {body}"

                    # Retry ONLY on retryable HTTP codes
                    if e.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print(
                            f"[WARN] {last_error} — retry "
                            f"{attempt}/{max_retries} in {wait:.1f}s",
                            flush=True,
                        )
                        time.sleep(wait)
                        continue

                    print(f"[WARN] {last_error} — trying next model...", flush=True)
                    break

                except (TimeoutError, socket.timeout) as e:
                    # Timeouts fail fast — do NOT retry
                    last_error = f"{provider['name']}/{model}: timeout after 90s"
                    print(f"[WARN] {last_error} — trying next model...", flush=True)
                    break

                except urllib.error.URLError as e:
                    # URLError may wrap a timeout — check the reason
                    if isinstance(getattr(e, "reason", None), (TimeoutError, socket.timeout)):
                        last_error = f"{provider['name']}/{model}: timeout after 90s"
                        print(f"[WARN] {last_error} — trying next model...", flush=True)
                        break

                    last_error = f"{provider['name']}/{model}: {e!r}"
                    if attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print(
                            f"[WARN] {last_error} — retry "
                            f"{attempt}/{max_retries} in {wait:.1f}s",
                            flush=True,
                        )
                        time.sleep(wait)
                        continue
                    print(f"[WARN] {last_error} — trying next model...", flush=True)
                    break

                except Exception as e:  # JSON parse, etc.
                    last_error = f"{provider['name']}/{model}: {e!r}"
                    if attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print(
                            f"[WARN] {last_error} — retry "
                            f"{attempt}/{max_retries} in {wait:.1f}s",
                            flush=True,
                        )
                        time.sleep(wait)
                        continue
                    print(f"[WARN] {last_error} — trying next model...", flush=True)
                    break

    return f"**[ERROR]** All configured LLM endpoints failed. Last error: {last_error}"


# ---------------------------------------------------------------------------
# Comment stripping that (a) preserves line numbers and (b) ignores strings
# ---------------------------------------------------------------------------
def strip_comments(code: str) -> str:
    out = []
    i, n = 0, len(code)
    quote = None
    while i < n:
        c = code[i]

        if quote is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:
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
            if nxt == "/":
                j = code.find("\n", i)
                if j == -1:
                    break
                i = j
                continue
            if nxt == "*":
                j = code.find("*/", i + 2)
                if j == -1:
                    break
                out.append("\n" * code[i:j + 2].count("\n"))
                i = j + 2
                continue

        out.append(c)
        i += 1

    return "".join(out)


# ---------------------------------------------------------------------------
# Slither (single run over project root, 5-minute hard cap)
# ---------------------------------------------------------------------------
def run_slither(root: str = ".") -> dict | None:
    output_json = "slither-report.json"
    if os.path.exists(output_json):
        os.remove(output_json)

    try:
        subprocess.run(
            ["slither", root, "--json", output_json],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=300,          # 5-minute hard cap
        )
    except subprocess.TimeoutExpired:
        print("[WARN] Slither timed out after 300s — skipping static analysis.",
              flush=True)
        return None
    except FileNotFoundError:
        print("[WARN] `slither` binary not found on PATH.", flush=True)
        return None

    if not os.path.exists(output_json):
        print("[WARN] Slither produced no output file (project build likely failed).",
              flush=True)
        return None

    try:
        with open(output_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Could not parse Slither JSON: {e}", flush=True)
        return None
    finally:
        try:
            os.remove(output_json)
        except OSError:
            pass

    if not data.get("success") or "results" not in data:
        print("[WARN] Slither JSON missing a valid 'results' block.", flush=True)
        return None

    return data["results"]


def _norm_path(p: str) -> str:
    p = (p or "").replace("\\", "/")
    if p:
        p = os.path.normpath(p)
    return p[2:] if p.startswith("./") else p


def findings_for_file(slither_results: dict | None, filepath: str) -> list:
    if not slither_results:
        return []

    target = _norm_path(filepath)
    findings = []

    for det in slither_results.get("detectors", []):
        elements = det.get("elements", [])
        if not elements:
            continue

        source_mapping = elements[0].get("source_mapping", {})
        rel_path = _norm_path(source_mapping.get("filename_relative", ""))
        if not rel_path:
            continue

        if (
            rel_path == target
            or rel_path.endswith("/" + target)
            or target.endswith("/" + rel_path)
        ):
            lines = source_mapping.get("lines", [])
            line_str = f"Line {lines[0]}" if lines else "Unknown line"
            findings.append({
                "severity": det.get("impact", "Unknown"),
                "confidence": det.get("confidence", "Unknown"),
                "title": det.get("check", ""),
                "description": det.get("description", ""),
                "instance": line_str,
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
# Chunked reduce (hierarchical: batches -> final)
# ---------------------------------------------------------------------------
def chunked_reduce(reports: list[str], batch_size: int = 8,
                   deadline: float | None = None) -> str:
    """Reduce in batches, then reduce the batch summaries.

    If a deadline (epoch seconds) is provided and exceeded, returns partial
    results rather than running past the budget.
    """
    if not reports:
        return "No per-file reports to synthesise."

    batches = [reports[i:i + batch_size] for i in range(0, len(reports), batch_size)]
    batch_summaries = []

    for idx, batch in enumerate(batches, 1):
        if deadline and time.time() > deadline:
            print(f"[WARN] Reduce batch {idx}/{len(batches)} skipped — budget exceeded",
                  flush=True)
            break

        print(f"[REDUCE] Batch {idx}/{len(batches)} ({len(batch)} files) ...",
              flush=True)

        joined = "\n".join(batch)
        if len(joined) > MAX_REDUCE_BATCH_CHARS:
            joined = (
                joined[:MAX_REDUCE_BATCH_CHARS]
                + "\n\n...[batch truncated for context budget]..."
            )

        batch_prompt = f"""Synthesise cross-contract findings from these file audits only. Precision over recall; drop anything unproven.

{joined}
"""
        batch_summaries.append(call_llm(batch_prompt, max_tokens=2000))

    if not batch_summaries:
        return (
            "**[REDUCE SKIPPED — budget exhausted before any batch ran]** "
            "See Part 2 for the individual audits."
        )

    if deadline and time.time() > deadline:
        print("[WARN] Final reduce synthesis skipped — budget exceeded", flush=True)
        return (
            "**[PARTIAL REDUCE — budget exceeded after batch summaries]**\n\n"
            "Batch summaries:\n\n" + "\n\n---\n\n".join(batch_summaries)
        )

    final_prompt = f"""You are the Lead Auditor producing the FINAL cross-contract report - the only thing the client sees. Precision over recall.

You are given batch summaries of per-file audits. Each finding is tagged Confirmed or Suspected (unverified). You may ONLY escalate a finding if:
(a) it is tagged Confirmed, OR
(b) it is tagged Suspected AND you can name the exact counterparty file that supplies the missing evidence, and that file appears in the batch summaries below.

Rules:
- DROP any finding that is generic, unproven, or not grounded in quoted code. If in doubt, drop it.
- DEDUPLICATE: same root cause across files -> one entry listing all locations.
- Do NOT invent new vulnerabilities. Synthesis and filtering only.
- Weight severity by real impact: fund loss > permanent lock > DoS > griefing > informational.

Output:

### Executive Summary
3-6 sentences. Overall risk posture. State how many confirmed issues by severity, and whether the codebase looks mature or early-stage.

### Confirmed Cross-Contract / Cross-Chain Issues
Per issue: Severity; Confidence; Components (`fileA:line` <-> `fileB:line`); Evidence (quoted from per-file findings); Attack path across contracts; Fix.
If none: `No confirmed cross-contract issues were substantiated by the per-file reviews.`

### Per-File Findings Worth Elevating (confirmed only, deduplicated)
Table: `file:line | severity | one-line issue`

### Coverage Gaps
Files not fully reviewed (truncated, read error, Slither build failure) and what was not checked.

### Prioritized Remediation
Ordered list, highest risk first.

Batch summaries:
{chr(10).join(batch_summaries)}
"""
    return call_llm(final_prompt, max_tokens=4000)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    START_TIME = time.time()
    MAP_DEADLINE = START_TIME + MAP_BUDGET_SECONDS
    REDUCE_DEADLINE = MAP_DEADLINE + REDUCE_BUDGET_SECONDS

    sol_files = discover_solidity_files()
    print(f"[INFO] Discovered {len(sol_files)} Solidity file(s) to audit.",
          flush=True)

    if not sol_files:
        with open("final-audit-report.md", "w", encoding="utf-8") as f:
            f.write(
                "# Cross-Chain Bridge Security Audit Report\n\n"
                "No Solidity files found to audit.\n"
            )
        return

    print("[INFO] Running Slither on project root...", flush=True)
    slither_results = run_slither(".")
    slither_ok = slither_results is not None

    per_file_reports = []

    for filepath in sol_files:
        if time.time() > MAP_DEADLINE:
            per_file_reports.append(
                f"## File: `{filepath}`\n\n"
                f"**[SKIPPED — runtime budget exceeded]** "
                f"This file was not audited because the pipeline hit its "
                f"{MAP_BUDGET_SECONDS // 60}-minute map-phase cap. "
                f"Re-run with a smaller file subset to cover it."
            )
            continue

        print(f"[MAP] Auditing {filepath} ...", flush=True)

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

        if slither_ok:
            slither_findings = json.dumps(
                findings_for_file(slither_results, filepath), indent=2
            )
        else:
            slither_findings = (
                "Slither did not produce output (project build may have failed). "
                "Perform the audit from code review only."
            )

        file_prompt = f"""You are a senior smart contract security auditor. Precision over recall: reporting zero issues is a correct outcome; a speculative finding is a defect in your work. Every finding is re-checked by a lead auditor and a human.

You are reviewing ONE file: `{filepath}`.

## Evidence rules (non-negotiable)
- Every finding MUST include: exact line number(s), a verbatim quote (1-8 lines) of the relevant code, and a concrete attack path (precondition -> call sequence -> impact).
- If you cannot quote the buggy code, DO NOT report the bug.
- Do NOT infer behavior from function names, comments, or NatSpec. Only from visible code.
- If the source is marked [TRUNCATED], do not speculate about the missing portion; say so.
- Reporting ZERO issues for a file is valid and expected. Do not manufacture findings.

## Required output (exact structure)

### A. File Summary (max 120 words)
Contract role; trust model (who is trusted to do what); external entrypoints; cross-chain/external calls.

### B. Slither Triage
For EACH Slither finding, one row: `[TP]` / `[FP]` / `[INCONCLUSIVE]`, check name + line, one-sentence justification citing code. End with: `Confirmed: N. Dismissed: M.`

### C. Independent Review - Confirmed Findings
Per finding:
- Severity: Critical / High / Medium / Low / Informational
- Confidence: High / Medium
- Location: `{filepath}:<line>`
- Evidence:
  ```solidity
  <verbatim quoted lines>
  ```
- Issue: one sentence.
- Attack path: precondition -> calls -> impact.
- Fix: concrete change.
If none, write exactly: `No confirmed findings.`

### D. Suspected but Unverified
Issues you cannot prove from this file alone. Same fields as C, plus **Missing evidence:** what you would need to confirm. These are NOT escalated unless corroborated.

### E. Explicit Non-Issues
List 2-5 things that LOOK suspicious but are actually safe, with the reason (cite the guard/ordering that makes them safe).

## Focus areas (verify each; state exposed / not exposed with the code that proves it)
- Source chain / source sender / endpoint authentication on inbound messages
- Replay protection (nonce, message hash, consumed flag)
- Mint/burn accounting vs lock/unlock invariants
- Access control on privileged ops (mint, pause, upgrade, peer registration)
- Reentrancy on external calls that mutate state
- Rounding / decimal handling
- Unchecked return values on token transfers

File: `{filepath}`

Slither Output:
```json
{slither_findings}
```

Solidity Code:
```solidity
{clean_code}
```"""
        llm_response = call_llm(file_prompt, max_tokens=3000)
        per_file_reports.append(f"## File: `{filepath}`\n\n{llm_response}")

    combined_file_reports = "\n\n---\n\n".join(per_file_reports)

    print("[REDUCE] Running cross-file bridge vulnerability analysis...", flush=True)

    if time.time() > REDUCE_DEADLINE:
        print("[WARN] Reduce budget exceeded — writing map-only report.", flush=True)
        cross_file_report = (
            "**[REDUCE SKIPPED — runtime budget exceeded]** "
            "The per-file audits below were produced successfully, but the "
            "cross-file synthesis step did not run because the map phase "
            "consumed the time budget. See Part 2 for the individual audits."
        )
    else:
        cross_file_report = chunked_reduce(
            per_file_reports, batch_size=8, deadline=REDUCE_DEADLINE
        )

    with open("final-audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Cross-Chain Bridge Security Audit Report\n\n")
        f.write("## Part 1: Cross-Contract & Cross-Chain Security Analysis\n\n")
        f.write(cross_file_report)
        f.write("\n\n---\n\n")
        f.write("## Part 2: Individual File Audits\n\n")
        f.write(combined_file_reports)

    elapsed = int(time.time() - START_TIME)
    print(f"[INFO] Audit complete in {elapsed}s. "
          f"Output written to final-audit-report.md", flush=True)


if __name__ == "__main__":
    main()
