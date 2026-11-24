import os
import glob
import json
import re
import subprocess
import time
import threading

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

FENCE = chr(96) * 3
MAX_CODE_CHARS = 50000
STAGE1_BATCH_TOKENS = 50000
STAGE1_MAX_TOKENS = 1024
STAGE2_MAX_TOKENS = 4000
MAP_BUDGET_SECONDS = 70 * 60

def est_tokens(text):
    return max(1, len(text) // 4)

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

def discover_solidity_files():
    excluded_dirs = {"node_modules", "lib", "test", "tests", "mock", "mocks", "script", "scripts", "out", "cache", "broadcast", "artifacts", ".git", ".github"}
    results = []
    for f in glob.glob("**/*.sol", recursive=True):
        if f.endswith((".t.sol", ".s.sol")):
            continue
        parts = f.replace("\\", "/").split("/")[:-1]
        if any(p in excluded_dirs for p in parts):
            continue
        if "/lib/" in "/" + f.replace("\\", "/") + "/":
            continue
        results.append(f)
    return sorted(results)

def _norm_path(p):
    p = (p or "").replace("\\", "/")
    if p:
        p = os.path.normpath(p)
    return p[2:] if p.startswith("./") else p

def run_slither(root="."):
    output_json = "slither-report.json"
    if os.path.exists(output_json):
        os.remove(output_json)
    print("[INFO] forge build --skip test ...", flush=True)
    try:
        fb = subprocess.run(["forge", "build", "--skip", "test"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
        print("[INFO] forge build exit: " + str(fb.returncode), flush=True)
        if fb.returncode != 0:
            print("[WARN] forge build stderr: " + fb.stderr.decode("utf-8", "ignore")[:2000], flush=True)
    except FileNotFoundError:
        print("[WARN] forge not found - install foundry-toolchain in YAML", flush=True)
    except Exception as e:
        print("[WARN] forge build error: " + str(e), flush=True)
    attempts = [
        ["slither", root, "--json", output_json, "--filter-paths", "node_modules,lib", "--exclude-dependencies"],
        ["slither", root, "--json", output_json, "--compile-force-framework", "solc", "--solc", "0.8.20", "--filter-paths", "node_modules,lib", "--exclude-dependencies"],
        ["slither", root, "--json", output_json, "--compile-force-framework", "solc", "--solc-remaps", "@openzeppelin/=lib/openzeppelin-contracts/", "--filter-paths", "node_modules,lib"],
    ]
    for idx, cmd in enumerate(attempts, 1):
        if os.path.exists(output_json):
            os.remove(output_json)
        print("[INFO] Slither attempt " + str(idx) + "/3", flush=True)
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=300)
            if os.path.exists(output_json):
                break
            print("[WARN] Slither attempt " + str(idx) + " exit=" + str(result.returncode) + " err=" + result.stderr.decode("utf-8", "ignore")[:1500], flush=True)
        except subprocess.TimeoutExpired:
            print("[WARN] Slither attempt " + str(idx) + " timeout", flush=True)
            continue
        except FileNotFoundError:
            print("[WARN] slither binary not found", flush=True)
            return None
    if not os.path.exists(output_json):
        print("[WARN] Slither produced no output after 3 attempts. Continuing LLM-only.", flush=True)
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
        print("[WARN] Slither JSON invalid. success=" + str(data.get("success")), flush=True)
        return None
    print("[INFO] Slither OK: " + str(len(data["results"].get("detectors", []))) + " detectors", flush=True)
    return data["results"]

def findings_for_file(slither_results, filepath):
    if not slither_results:
        return []
    target = _norm_path(filepath)
    findings = []
    for det in slither_results.get("detectors", []):
        elements = det.get("elements", [])
        if not elements:
            continue
        sm = elements[0].get("source_mapping", {})
        rel = _norm_path(sm.get("filename_relative", ""))
        if not rel:
            continue
        if rel == target or rel.endswith("/" + target) or target.endswith("/" + rel):
            lines = sm.get("lines", [])
            findings.append({"severity": det.get("impact", "Unknown"), "confidence": det.get("confidence", "Unknown"), "title": det.get("check", ""), "description": det.get("description", ""), "line": lines[0] if lines else None})
    return findings

CF_ACCOUNTS = []
for i in (1, 2, 3):
    aid = os.environ.get("CF_ACCOUNT_ID_" + str(i), "").strip()
    tok = os.environ.get("CF_API_TOKEN_" + str(i), "").strip()
    if aid and tok:
        CF_ACCOUNTS.append({"id": aid, "token": tok, "exhausted": False, "label": "CF-" + str(i)})

CF_PRIMARY = "@cf/google/gemma-4-26b-a4b-it"
CF_FALLBACK = "@cf/meta/llama-4-scout-17b-16e-instruct"
_cf_rr = 0
_cf_lock = threading.Lock()

def cf_call(prompt_json_instruction, batch_text, max_tokens=1024):
    global _cf_rr
    if not CF_ACCOUNTS:
        print("[WARN] No Cloudflare accounts configured", flush=True)
        return None
    import urllib.request
    import urllib.error
    for attempt in range(len(CF_ACCOUNTS) * 2):
        with _cf_lock:
            idx = _cf_rr % len(CF_ACCOUNTS)
            _cf_rr += 1
        acct = CF_ACCOUNTS[idx]
        if acct["exhausted"]:
            continue
        model = CF_PRIMARY
        for model_try in (CF_PRIMARY, CF_FALLBACK):
            url = "https://api.cloudflare.com/client/v4/accounts/" + acct["id"] + "/ai/run/" + model
            payload = json.dumps({"messages": [{"role": "system", "content": "You output strict JSON only. No markdown, no explanation."}, {"role": "user", "content": prompt_json_instruction + "\n\n" + batch_text}], "max_tokens": max_tokens}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Authorization": "Bearer " + acct["token"], "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                if not data.get("success"):
                    print("[WARN] " + acct["label"] + " CF error: " + str(data.get("errors"))[:500], flush=True)
                    continue
                content = ((data.get("result") or {}).get("response") or "").strip()
                if not content:
                    continue
                content = content.replace(FENCE + "json", "").replace(FENCE, "").strip()
                try:
                    parsed = json.loads(content)
                    return parsed
                except Exception:
                    m = re.search(r"\{.*\}", content, re.DOTALL)
                    if m:
                        try:
                            return json.loads(m.group(0))
                        except Exception:
                            pass
                    print("[WARN] " + acct["label"] + " CF returned non-JSON, trying fallback model", flush=True)
                    continue
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", "ignore")[:500]
                except Exception:
                    pass
                print("[WARN] " + acct["label"] + " CF HTTP " + str(e.code) + " " + body, flush=True)
                if e.code == 429:
                    acct["exhausted"] = True
                    print("[INFO] " + acct["label"] + " marked exhausted (429 Neuron limit)", flush=True)
                    break
                if e.code in (401, 403):
                    acct["exhausted"] = True
                    break
                continue
            except Exception as e:
                print("[WARN] " + acct["label"] + " CF exception: " + repr(e), flush=True)
                continue
    return None

GONKA_MODELS = ["deepseek-ai/DeepSeek-V4-Flash-0731", "zai-org/GLM-5.3-Flash", "MiniMaxAI/MiniMax-M2.7"]
GONKA_KEYS = []
for i in (1, 2, 3):
    k = os.environ.get("GONKA_KEY_" + str(i), "").strip()
    if k:
        GONKA_KEYS.append(k)
GONKA_BASE = os.environ.get("GONKA_BASE_URL", "https://api.gonka.ai/v1").strip()
_gonka_exhausted = set()
_gonka_lock = threading.Lock()

def gonka_call(prompt, max_tokens=4000):
    if OpenAI is None:
        print("[ERROR] openai SDK not installed. pip install openai", flush=True)
        return "**[ERROR]** openai SDK missing"
    if not GONKA_KEYS:
        return "**[ERROR]** No GONKA keys configured"
    last_err = ""
    for model in GONKA_MODELS:
        for ki, key in enumerate(GONKA_KEYS):
            pair = (model, ki)
            with _gonka_lock:
                if pair in _gonka_exhausted:
                    continue
            print("[GONKA] Trying model=" + model + " key=" + str(ki + 1), flush=True)
            try:
                client = OpenAI(base_url=GONKA_BASE, api_key=key, timeout=180.0, max_retries=0)
                resp = client.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}], temperature=0.0, max_tokens=max_tokens)
                content = (resp.choices[0].message.content or "").strip()
                if content:
                    return "*Model: `" + model + "` | Key: " + str(ki + 1) + "*\n\n" + content
                last_err = "empty content"
            except Exception as e:
                msg = str(e)
                last_err = msg[:500]
                print("[WARN] Gonka " + model + " key " + str(ki + 1) + " failed: " + last_err, flush=True)
                if "402" in msg or "429" in msg or "quota" in msg.lower() or "exhausted" in msg.lower() or "insufficient" in msg.lower():
                    with _gonka_lock:
                        _gonka_exhausted.add(pair)
                    print("[INFO] Marked exhausted: " + model + " key " + str(ki + 1), flush=True)
                    continue
                if "401" in msg or "403" in msg:
                    with _gonka_lock:
                        _gonka_exhausted.add(pair)
                    continue
                time.sleep(3)
                continue
    return "**[ERROR]** All Gonka (model, key) pairs exhausted. Last: " + last_err

def stage1_triage(files_with_code, slither_map):
    batches = []
    cur = []
    cur_tokens = 0
    for fp, code in files_with_code:
        sl = slither_map.get(fp, [])
        sl_text = json.dumps(sl, indent=0)[:3000] if sl else "No Slither findings."
        chunk = "FILE: " + fp + "\nSLITHER: " + sl_text + "\nCODE:\n" + code + "\n---END FILE---\n"
        toks = est_tokens(chunk)
        if cur and cur_tokens + toks > STAGE1_BATCH_TOKENS:
            batches.append(cur)
            cur = []
            cur_tokens = 0
        cur.append(chunk)
        cur_tokens += toks
    if cur:
        batches.append(cur)
    print("[STAGE1] " + str(len(files_with_code)) + " files -> " + str(len(batches)) + " batches", flush=True)
    critical = {}
    for bi, batch in enumerate(batches, 1):
        print("[STAGE1] Batch " + str(bi) + "/" + str(len(batches)), flush=True)
        batch_text = "\n".join(batch)
        instr = "You are a Solidity triage auditor. Return STRICT JSON only: {\"critical_files\": [{\"path\": \"...\", \"reason\": \"...\"}]}. Include ONLY files with probable HIGH severity: fund loss, unauthorized mint/burn, broken access control on privileged ops, reentrancy with state mutation, missing authentication on cross-chain inbound, replayable mint, broken accounting. If a file is Low/Info or clean, EXCLUDE it. If none, return {\"critical_files\": []}. Do NOT invent. Base only on quoted code + Slither."
        parsed = cf_call(instr, batch_text, max_tokens=STAGE1_MAX_TOKENS)
        if not parsed:
            print("[WARN] Stage1 batch " + str(bi) + " returned no result - treating as no HIGH files", flush=True)
            continue
        for item in parsed.get("critical_files", []) or []:
            p = item.get("path", "")
            if p and p not in critical:
                critical[p] = item.get("reason", "")
    return critical

def stage2_deep_audit(filepath, code, slither_findings, all_files_map):
    imports = re.findall(r"import\s+(?:\{[^}]+\}\s+from\s+)?[\"']([^\"']+)[\"']", code)
    dep_text = ""
    for imp in imports[:5]:
        base = os.path.basename(imp)
        for fp2, c2 in all_files_map.items():
            if fp2.endswith(base) or os.path.basename(fp2) == base:
                dep_text += "\nDEPENDENCY " + fp2 + ":\n" + c2[:8000] + "\n"
                break
    prompt = "You are a senior smart contract security auditor. Precision over recall. Every finding MUST have exact line, verbatim quote (1-8 lines), concrete attack path. If you cannot quote buggy code, DO NOT report it. Reporting zero issues is valid.\n\nFILE: " + filepath + "\n\nSLITHER:\n" + FENCE + "json\n" + json.dumps(slither_findings, indent=2) + "\n" + FENCE + "\n\nCODE:\n" + FENCE + "solidity\n" + code + "\n" + FENCE + "\n\nDEPENDENCIES (truncated):\n" + dep_text + "\n\nOUTPUT Markdown:\n### A. Summary (max 120 words)\n### B. Slither Triage - each finding [TP]/[FP]/[INCONCLUSIVE] + 1 sentence + Confirmed: N Dismissed: M\n### C. Confirmed Findings - per finding: Severity, Confidence, Location file:line, Evidence code block, Issue, Attack path, Fix. If none: No confirmed findings.\n### D. Suspected but Unverified - same + Missing evidence\n### E. Explicit Non-Issues - 2-5 looks-suspicious-but-safe with guard cited\n### Focus Areas: source chain/sender auth, replay, mint/burn vs lock/unlock, access control, reentrancy, rounding/decimals, unchecked returns - each exposed/not exposed with code proof."
    return gonka_call(prompt, max_tokens=STAGE2_MAX_TOKENS)

def main():
    start = time.time()
    files = discover_solidity_files()
    print("[INFO] Discovered " + str(len(files)) + " Solidity files", flush=True)
    if not files:
        open("audit-report.md", "w", encoding="utf-8").write("# Audit Report\n\nNo Solidity files found.\n")
        return
    slither_results = run_slither(".")
    slither_map = {}
    if slither_results:
        for fp in files:
            slither_map[fp] = findings_for_file(slither_results, fp)
    files_with_code = []
    all_map = {}
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError as e:
            print("[WARN] Cannot read " + fp + ": " + str(e), flush=True)
            continue
        clean = strip_comments(raw)
        if len(clean) > MAX_CODE_CHARS:
            clean = clean[:MAX_CODE_CHARS] + "\n// ...[TRUNCATED]..."
        files_with_code.append((fp, clean))
        all_map[fp] = clean
    critical = stage1_triage(files_with_code, slither_map)
    print("[INFO] Stage1 HIGH files: " + str(len(critical)) + " -> " + ", ".join(critical.keys()), flush=True)
    if not critical:
        with open("audit-report.md", "w", encoding="utf-8") as f:
            f.write("# Cross-Chain Bridge Security Audit Report\n\n## Part 1: Triage\n\nNo HIGH risk files flagged by Stage 1 (Cloudflare Gemma-4-26B).\n\nAudited files: " + str(len(files_with_code)) + "\n\n## Part 2: Slither Summary\n\n")
            for fp in files:
                f.write("### " + fp + "\nSlither findings: " + str(len(slither_map.get(fp, []))) + "\n\n")
        print("[INFO] Done - no HIGH files, no Stage2 needed", flush=True)
        return
    per_file = []
    for fp in critical.keys():
        if time.time() > start + MAP_BUDGET_SECONDS:
            per_file.append("## File: `" + fp + "`\n\n**[SKIPPED - budget exceeded]**\n")
            print("[MAP] SKIPPED " + fp, flush=True)
            continue
        code = all_map.get(fp, "")
        if not code:
            print("[WARN] Critical file not in map (path mismatch): " + fp, flush=True)
            for k in all_map.keys():
                if k.endswith(fp) or fp.endswith(k):
                    code = all_map[k]
                    fp = k
                    break
        print("[STAGE2] Deep audit " + fp, flush=True)
        report = stage2_deep_audit(fp, code, slither_map.get(fp, []), all_map)
        per_file.append("## File: `" + fp + "`\n\n**Stage1 reason:** " + critical.get(fp, "") + "\n\n" + report)
    with open("audit-report.md", "w", encoding="utf-8") as f:
        f.write("# Cross-Chain Bridge Security Audit Report\n\n## Part 1: Cross-Contract / Cross-Chain Analysis\n\nStage 1 flagged " + str(len(critical)) + " HIGH files. Stage 2 deep audit below.\n\nHIGH files:\n")
        for k, v in critical.items():
            f.write("- `" + k + "` - " + v + "\n")
        f.write("\n---\n\n## Part 2: Deep Audits (" + str(len(per_file)) + " files)\n\n")
        f.write("\n\n---\n\n".join(per_file))
    print("[INFO] Done in " + str(int(time.time() - start)) + "s. Output audit-report.md", flush=True)

if __name__ == "__main__":
    main()
