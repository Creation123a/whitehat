import os
import glob
import json
import re
import subprocess
import time
import urllib.request
import urllib.error
import threading
import socket

FENCE = chr(96) * 3

MAX_CODE_CHARS = 60000
MAX_REDUCE_BATCH_CHARS = 150000

MAP_BUDGET_SECONDS = 40 * 60
REDUCE_BUDGET_SECONDS = 8 * 60

_zai_lock = threading.Lock()
_zai_last_call = 0.0
ZAI_MIN_INTERVAL = 1.2

_mistral_lock = threading.Lock()
_mistral_last_call = 0.0
MISTRAL_MIN_INTERVAL = 1.0

def _zai_wait():
    global _zai_last_call
    with _zai_lock:
        now = time.time()
        gap = now - _zai_last_call
        if gap < ZAI_MIN_INTERVAL:
            time.sleep(ZAI_MIN_INTERVAL - gap)
        _zai_last_call = time.time()

def _mistral_wait():
    global _mistral_last_call
    with _mistral_lock:
        now = time.time()
        gap = now - _mistral_last_call
        if gap < MISTRAL_MIN_INTERVAL:
            time.sleep(MISTRAL_MIN_INTERVAL - gap)
        _mistral_last_call = time.time()

PROVIDERS = [
    {
        "name": "Z.ai GLM",
        "url": "https://api.z.ai/api/paas/v4/chat/completions",
        "key_env": "ZAI_API_KEY",
        "rate_limit_fn": _zai_wait,
        "max_retries_per_model": 2,
        "backoff_seconds": 3.0,
        "timeout": 120,
        "models": ["glm-4.7-flash", "glm-4.5-flash"],
        "model_options": {},
    },
    {
        "name": "Mistral",
        "url": "https://api.mistral.ai/v1/chat/completions",
        "key_env": "MISTRAL_API_KEY",
        "rate_limit_fn": _mistral_wait,
        "max_retries_per_model": 1,
        "backoff_seconds": 2.0,
        "timeout": 90,
        "models": ["codestral-latest", "mistral-small-latest"],
        "model_options": {},
    },
]

def call_llm(prompt, max_tokens=3000):
    last_error = "no provider configured with an API key"
    for provider in PROVIDERS:
        api_key = os.environ.get(provider["key_env"], "").strip()
        if not api_key:
            print("[INFO] Skipping " + provider["name"] + " - no API key in env", flush=True)
            continue
        rl_fn = provider.get("rate_limit_fn")
        max_retries = provider.get("max_retries_per_model", 1)
        backoff = provider.get("backoff_seconds", 2.0)
        timeout = provider.get("timeout", 90)
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
                "Authorization": "Bearer " + api_key,
                "Content-Type": "application/json",
                "User-Agent": "Slither-LLM-Auditor/2.0",
            }
            for attempt in range(1, max_retries + 1):
                if rl_fn:
                    rl_fn()
                req = urllib.request.Request(provider["url"], data=payload, headers=req_headers)
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    choices = data.get("choices") or []
                    if not choices:
                        last_error = provider["name"] + "/" + model + ": empty choices"
                        break
                    content = (choices[0].get("message") or {}).get("content")
                    if isinstance(content, list):
                        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
                    content = (content or "").strip()
                    if not content:
                        last_error = provider["name"] + "/" + model + ": empty content"
                        break
                    return "*Model: `" + model + "`*\n\n" + content
                except urllib.error.HTTPError as e:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", "ignore")[:300]
                    except Exception:
                        pass
                    last_error = provider["name"] + "/" + model + ": HTTP " + str(e.code) + " " + body
                    if e.code in (401, 403):
                        print("[WARN] " + last_error + " - key invalid or API access disabled, trying next provider...", flush=True)
                        break
                    if e.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print("[WARN] " + last_error + " - retry " + str(attempt) + "/" + str(max_retries) + " in " + str(round(wait, 1)) + "s", flush=True)
                        time.sleep(wait)
                        continue
                    print("[WARN] " + last_error + " - trying next model...", flush=True)
                    break
                except (TimeoutError, socket.timeout):
                    last_error = provider["name"] + "/" + model + ": timeout after " + str(timeout) + "s"
                    print("[WARN] " + last_error + " - trying next model...", flush=True)
                    break
                except urllib.error.URLError as e:
                    if isinstance(getattr(e, "reason", None), (TimeoutError, socket.timeout)):
                        last_error = provider["name"] + "/" + model + ": timeout after " + str(timeout) + "s"
                        print("[WARN] " + last_error + " - trying next model...", flush=True)
                        break
                    last_error = provider["name"] + "/" + model + ": " + repr(e)
                    if attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print("[WARN] " + last_error + " - retry " + str(attempt) + "/" + str(max_retries) + " in " + str(round(wait, 1)) + "s", flush=True)
                        time.sleep(wait)
                        continue
                    print("[WARN] " + last_error + " - trying next model...", flush=True)
                    break
                except Exception as e:
                    last_error = provider["name"] + "/" + model + ": " + repr(e)
                    if attempt < max_retries:
                        wait = backoff * (2 ** (attempt - 1))
                        print("[WARN] " + last_error + " - retry " + str(attempt) + "/" + str(max_retries) + " in " + str(round(wait, 1)) + "s", flush=True)
                        time.sleep(wait)
                        continue
                    print("[WARN] " + last_error + " - trying next model...", flush=True)
                    break
    return "**[ERROR]** All configured LLM endpoints failed. Last error: " + last_error

def strip_comments(code):
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

def run_slither(root="."):
    output_json = "slither-report.json"
    if os.path.exists(output_json):
        os.remove(output_json)
    try:
        subprocess.run(
            ["slither", root, "--json", output_json],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        print("[WARN] Slither timed out after 300s - skipping static analysis.", flush=True)
        return None
    except FileNotFoundError:
        print("[WARN] `slither` binary not found on PATH.", flush=True)
        return None
    if not os.path.exists(output_json):
        print("[WARN] Slither produced no output file (project build likely failed).", flush=True)
        return None
    try:
        with open(output_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("[WARN] Could not parse Slither JSON: " + str(e), flush=True)
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

def _norm_path(p):
    p = (p or "").replace("\\", "/")
    if p:
        p = os.path.normpath(p)
    return p[2:] if p.startswith("./") else p

def findings_for_file(slither_results, filepath):
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
        if rel_path == target or rel_path.endswith("/" + target) or target.endswith("/" + rel_path):
            lines = source_mapping.get("lines", [])
            line_str = "Line " + str(lines[0]) if lines else "Unknown line"
            findings.append({
                "severity": det.get("impact", "Unknown"),
                "confidence": det.get("confidence", "Unknown"),
                "title": det.get("check", ""),
                "description": det.get("description", ""),
                "instance": line_str,
            })
    return findings

def discover_solidity_files():
    excluded_dirs = {
        "node_modules", "lib", "test", "tests", "mock", "mocks",
        "script", "scripts", "out", "cache", "broadcast", "artifacts",
        ".git", ".github",
    }
    results = []
    for f in glob.glob("**/*.sol", recursive=True):
        if f.endswith((".t.sol", ".s.sol")):
            continue
        parts = _norm_path(f).split("/")[:-1]
        if any(p in excluded_dirs for p in parts):
            continue
        if "/lib/" in "/" + _norm_path(f) + "/":
            continue
        results.append(f)
    return sorted(results)

def is_critical_file(slither_findings, llm_report):
    for f in slither_findings or []:
        sev = str(f.get("severity", "")).lower()
        if sev in ("high", "critical"):
            return True
    if not llm_report:
        return False
    if "No confirmed findings." in llm_report:
        return False
    if re.search(r"Severity:\s*(Critical|High|Medium)", llm_report, re.IGNORECASE):
        return True
    if re.search(r"Confirmed:\s*[1-9]", llm_report):
        return True
    return False

def chunked_reduce(reports, batch_size=8, deadline=None):
    if not reports:
        return "No per-file reports to synthesise."
    batches = [reports[i:i + batch_size] for i in range(0, len(reports), batch_size)]
    batch_summaries = []
    for idx, batch in enumerate(batches, 1):
        if deadline and time.time() > deadline:
            print("[WARN] Reduce batch " + str(idx) + "/" + str(len(batches)) + " skipped - budget exceeded", flush=True)
            break
        print("[REDUCE] Batch " + str(idx) + "/" + str(len(batches)) + " (" + str(len(batch)) + " files) ...", flush=True)
        joined = "\n".join(batch)
        if len(joined) > MAX_REDUCE_BATCH_CHARS:
            joined = joined[:MAX_REDUCE_BATCH_CHARS] + "\n\n...[batch truncated for context budget]..."
        batch_prompt = "Synthesise cross-contract findings from these file audits only. Precision over recall; drop anything unproven.\n\n" + joined + "\n"
        batch_summaries.append(call_llm(batch_prompt, max_tokens=2000))
    if not batch_summaries:
        return "**[REDUCE SKIPPED - budget exhausted before any batch ran]** See Part 2 for the individual audits."
    if deadline and time.time() > deadline:
        print("[WARN] Final reduce synthesis skipped - budget exceeded", flush=True)
        return "**[PARTIAL REDUCE - budget exceeded after batch summaries]**\n\nBatch summaries:\n\n" + "\n\n---\n\n".join(batch_summaries)
    final_prompt = "You are the Lead Auditor producing the FINAL cross-contract report - the only thing the client sees. Precision over recall.\n\nYou are given batch summaries of per-file audits. Each finding is tagged Confirmed or Suspected (unverified). You may ONLY escalate a finding if:\n(a) it is tagged Confirmed, OR\n(b) it is tagged Suspected AND you can name the exact counterparty file that supplies the missing evidence, and that file appears in the batch summaries below.\n\nRules:\n- DROP any finding that is generic, unproven, or not grounded in quoted code. If in doubt, drop it.\n- DEDUPLICATE: same root cause across files -> one entry listing all locations.\n- Do NOT invent new vulnerabilities. Synthesis and filtering only.\n- Weight severity by real impact: fund loss > permanent lock > DoS > griefing > informational.\n\nOutput:\n\n### Executive Summary\n3-6 sentences. Overall risk posture. State how many confirmed issues by severity, and whether the codebase looks mature or early-stage.\n\n### Confirmed Cross-Contract / Cross-Chain Issues\nPer issue: Severity; Confidence; Components (`fileA:line` <-> `fileB:line`); Evidence (quoted from per-file findings); Attack path across contracts; Fix.\nIf none: `No confirmed cross-contract issues were substantiated by the per-file reviews.`\n\n### Per-File Findings Worth Elevating (confirmed only, deduplicated)\nTable: `file:line | severity | one-line issue`\n\n### Coverage Gaps\nFiles not fully reviewed (truncated, read error, Slither build failure) and what was not checked.\n\n### Prioritized Remediation\nOrdered list, highest risk first.\n\nBatch summaries:\n" + chr(10).join(batch_summaries) + "\n"
    return call_llm(final_prompt, max_tokens=4000)

def main():
    START_TIME = time.time()
    MAP_DEADLINE = START_TIME + MAP_BUDGET_SECONDS
    REDUCE_DEADLINE = MAP_DEADLINE + REDUCE_BUDGET_SECONDS
    sol_files = discover_solidity_files()
    print("[INFO] Discovered " + str(len(sol_files)) + " Solidity file(s) to audit (lib/test/mocks/.t.sol/.s.sol excluded).", flush=True)
    if not sol_files:
        with open("final-audit-report.md", "w", encoding="utf-8") as f:
            f.write("# Cross-Chain Bridge Security Audit Report\n\nNo Solidity files found to audit.\n")
        return
    print("[INFO] Running Slither on project root (all files, including deps for call-graph)...", flush=True)
    slither_results = run_slither(".")
    slither_ok = slither_results is not None
    per_file_reports = []
    critical_reports = []
    skipped_files = []
    for filepath in sol_files:
        if time.time() > MAP_DEADLINE:
            per_file_reports.append("## File: `" + filepath + "`\n\n**[SKIPPED - runtime budget exceeded]** This file was not audited because the pipeline hit its " + str(MAP_BUDGET_SECONDS // 60) + "-minute map-phase cap. Re-run with a smaller file subset to cover it.")
            skipped_files.append(filepath)
            continue
        print("[MAP] Auditing " + filepath + " ...", flush=True)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError as e:
            per_file_reports.append("## File: `" + filepath + "`\n\n**[ERROR]** Could not read file: " + str(e))
            continue
        clean_code = strip_comments(raw)
        if len(clean_code) > MAX_CODE_CHARS:
            clean_code = clean_code[:MAX_CODE_CHARS] + "\n// ...[TRUNCATED: file too large for LLM context]..."
        if slither_ok:
            slither_findings = findings_for_file(slither_results, filepath)
            slither_findings_str = json.dumps(slither_findings, indent=2)
        else:
            slither_findings = []
            slither_findings_str = "Slither did not produce output (project build may have failed). Perform the audit from code review only."
        file_prompt = "You are a senior smart contract security auditor. Precision over recall: reporting zero issues is a correct outcome; a speculative finding is a defect in your work. Every finding is re-checked by a lead auditor and a human.\n\nYou are reviewing ONE file: `" + filepath + "`.\n\n## Evidence rules (non-negotiable)\n- Every finding MUST include: exact line number(s), a verbatim quote (1-8 lines) of the relevant code, and a concrete attack path (precondition -> call sequence -> impact).\n- If you cannot quote the buggy code, DO NOT report the bug.\n- Do NOT infer behavior from function names, comments, or NatSpec. Only from visible code.\n- If the source is marked [TRUNCATED], do not speculate about the missing portion; say so.\n- Reporting ZERO issues for a file is valid and expected. Do not manufacture findings.\n\n## Required output (exact structure)\n\n### A. File Summary (max 120 words)\nContract role; trust model (who is trusted to do what); external entrypoints; cross-chain/external calls.\n\n### B. Slither Triage\nFor EACH Slither finding, one row: `[TP]` / `[FP]` / `[INCONCLUSIVE]`, check name + line, one-sentence justification citing code. End with: `Confirmed: N. Dismissed: M.`\n\n### C. Independent Review - Confirmed Findings\nPer finding:\n- Severity: Critical / High / Medium / Low / Informational\n- Confidence: High / Medium\n- Location: `" + filepath + ":<line>`\n- Evidence:\n" + FENCE + "solidity\n<verbatim quoted lines>\n" + FENCE + "\n- Issue: one sentence.\n- Attack path: precondition -> calls -> impact.\n- Fix: concrete change.\nIf none, write exactly: `No confirmed findings.`\n\n### D. Suspected but Unverified\nIssues you cannot prove from this file alone. Same fields as C, plus **Missing evidence:** what you would need to confirm. These are NOT escalated unless corroborated.\n\n### E. Explicit Non-Issues\nList 2-5 things that LOOK suspicious but are actually safe, with the reason (cite the guard/ordering that makes them safe).\n\n## Focus areas (verify each; state exposed / not exposed with the code that proves it)\n- Source chain / source sender / endpoint authentication on inbound messages\n- Replay protection (nonce, message hash, consumed flag)\n- Mint/burn accounting vs lock/unlock invariants\n- Access control on privileged ops (mint, pause, upgrade, peer registration)\n- Reentrancy on external calls that mutate state\n- Rounding / decimal handling\n- Unchecked return values on token transfers\n\nFile: `" + filepath + "`\n\nSlither Output:\n" + FENCE + "json\n" + slither_findings_str + "\n" + FENCE + "\n\nSolidity Code:\n" + FENCE + "solidity\n" + clean_code + "\n" + FENCE + "\n"
        llm_response = call_llm(file_prompt, max_tokens=3000)
        full_report = "## File: `" + filepath + "`\n\n" + llm_response
        per_file_reports.append(full_report)
        if is_critical_file(slither_findings, llm_response):
            critical_reports.append(full_report)
            print("[MAP] " + filepath + " -> CRITICAL, will go to Reduce", flush=True)
        else:
            print("[MAP] " + filepath + " -> clean / low, skipped from Reduce", flush=True)
    combined_file_reports = "\n\n---\n\n".join(per_file_reports)
    print("[REDUCE] Running cross-file analysis on " + str(len(critical_reports)) + "/" + str(len(per_file_reports)) + " critical files only...", flush=True)
    if time.time() > REDUCE_DEADLINE:
        print("[WARN] Reduce budget exceeded - writing map-only report.", flush=True)
        cross_file_report = "**[REDUCE SKIPPED - runtime budget exceeded]** The per-file audits below were produced successfully, but the cross-file synthesis step did not run because the map phase consumed the time budget. See Part 2 for the individual audits."
    elif not critical_reports:
        cross_file_report = "No confirmed cross-contract issues were substantiated by the per-file reviews.\n\nAll " + str(len(per_file_reports)) + " filtered files were audited in Map phase. None met the Critical threshold (Slither High/Critical OR LLM Confirmed Critical/High/Medium) to escalate to Reduce phase."
    else:
        cross_file_report = chunked_reduce(critical_reports, batch_size=8, deadline=REDUCE_DEADLINE)
    with open("final-audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Cross-Chain Bridge Security Audit Report\n\n")
        f.write("## Part 1: Cross-Contract & Cross-Chain Security Analysis\n\n")
        f.write(cross_file_report)
        f.write("\n\n---\n\n")
        f.write("## Part 2: Individual File Audits\n\n")
        f.write(combined_file_reports)
    elapsed = int(time.time() - START_TIME)
    print("[INFO] Audit complete in " + str(elapsed) + "s. Map=" + str(len(per_file_reports)) + " files, Reduce=" + str(len(critical_reports)) + " critical files. Output written to final-audit-report.md", flush=True)

if __name__ == "__main__":
    main()
