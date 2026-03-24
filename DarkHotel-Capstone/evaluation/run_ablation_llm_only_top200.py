"""
DarkHotel Ablation Study - LLM Only on GPTScan Top200
Sends raw Solidity code directly to Gemini (no Slither, no RAG).
Measures False Positive Rate when LLM works alone.

All 225 contracts are SAFE -> any VULNERABLE = False Positive.

Usage:
    cd evaluation && python run_ablation_llm_only_top200.py
    Resume:  python run_ablation_llm_only_top200.py --resume
"""

import os
import sys
import json
import re
import time
import argparse
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load API key from backend/.env
BACKEND_DIR = Path(__file__).parent.parent / "backend"
load_dotenv(BACKEND_DIR / ".env")

API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-pro")

if not API_KEY:
    print("ERROR: No API key found. Set GEMINI_API_KEY in backend/.env")
    sys.exit(1)

from google import genai

# --- CONFIG ---
DATASET_DIR = Path(__file__).parent / "external_datasets" / "GPTScan-Top200"
OUTPUT_FILE = Path(__file__).parent / "ablation_llm_only_top200_results.json"
CHECKPOINT_FILE = Path(__file__).parent / "ablation_llm_only_top200_checkpoint.json"

DELAY_BETWEEN_CALLS = 3
MIN_FILE_LINES = 10

ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}


def create_only_llm_prompt(code: str) -> str:
    """Same prompt as llm_analyzer.py but with empty Slither + empty RAG."""

    slither_section = """## STATIC ANALYSIS (Slither):
- No Slither analysis available"""

    rag_section = """## HISTORICAL CASES:
No similar cases found in database."""

    prompt = f"""You are an expert blockchain security auditor. Your task is to SYSTEMATICALLY check the Solidity code for the following 3 vulnerability types.

{slither_section}

{rag_section}

## CODE TO ANALYZE:
```solidity
{code}
```

## SYSTEMATIC VULNERABILITY CHECKLIST:

You MUST check ALL 3 vulnerability types below. For EACH type, explicitly state YES or NO with evidence.

### 1. REENTRANCY (SWC-107)
- Check: Are there external calls using `.call{{value:}}()` BEFORE state updates?
- VULNERABLE: State changes happen AFTER `.call{{value:}}()` external calls
- NOT VULNERABLE (do NOT report):
  - `.send()` and `.transfer()` only forward 2300 gas — NOT enough to reenter
  - ReentrancyGuard / nonReentrant modifier is used
  - Checks-Effects-Interactions pattern is followed (state updated BEFORE external call)
  - No external call exists in the function
  - ERC20/IERC20 token calls (`.transfer()`, `.transferFrom()`, `.approve()`) are HIGH-LEVEL interface calls, NOT raw `.call{{value:}}()`. They CANNOT cause reentrancy in the caller contract. Do NOT report SWC-107 for ERC20 token operations
  - If a mutex/lock pattern is used (bool locked, require(!locked), locked = true/false)
- Answer: [YES/NO] with evidence

### 2. INTEGER OVERFLOW/UNDERFLOW (SWC-101)
- **FIRST CHECK THE PRAGMA VERSION** before anything else:
  - If pragma solidity >= 0.8.0 (e.g., ^0.8.0, ^0.8.4, ^0.8.26, >=0.8.0) → SWC-101 is IMPOSSIBLE. Solidity 0.8.x has built-in overflow/underflow checks that auto-revert. STOP HERE, answer NO, do NOT analyze arithmetic.
- Only if Solidity < 0.8.0: Check if math operations (+, -, *, /) are done WITHOUT SafeMath AND with exploitable impact
- VULNERABLE: Solidity < 0.8.0 + no SafeMath + arithmetic affects balances, token amounts, or access control
- NOT VULNERABLE (do NOT report):
  - Solidity >= 0.8.0 (built-in overflow protection) — THIS IS ABSOLUTE, no exceptions
  - SafeMath library is used for the operation
  - Arithmetic only affects non-critical values (loop counters, timestamps, array indices, display values)
  - The overflow/underflow has no realistic exploit path (cannot be triggered by user input)
- Answer: [YES/NO] with evidence of EXPLOITABLE impact

### 3. UNCHECKED RETURN VALUE (SWC-104)
- Check: Are LOW-LEVEL calls (.send(), .call()) used WITHOUT checking the return value?
- VULNERABLE: addr.send(amount) or addr.call() without require() or if() check
- NOT VULNERABLE (do NOT report):
  - Return value is checked with require() or if()
  - .transfer() is used (auto-reverts on failure)
  - The call result is captured in a bool and checked
  - ERC20/IERC20 `.transfer()` and `.transferFrom()` are HIGH-LEVEL function calls with built-in revert — they are NOT the same as low-level `.call()`. Do NOT report SWC-104 for ERC20 token operations
- Answer: [YES/NO] with evidence

## OUTPUT FORMAT (STRICT JSON):

After checking ALL 3 types, identify the MOST DANGEROUS vulnerability as primary. Any lesser findings go to secondary_warnings.

{{
  "verdict": "VULNERABLE or SAFE",
  "confidence": "HIGH or MEDIUM or LOW",
  "primary_vulnerability": {{
    "type": "Vulnerability Type Name",
    "swc_id": "SWC-XXX",
    "severity": "Critical or High or Medium or Low",
    "location": "function_name() at line X",
    "description": "Clear explanation of the vulnerability",
    "exploit_scenario": "Step-by-step how an attacker could exploit this",
    "recommendation": "Specific fix recommendation"
  }},
  "secondary_warnings": [
    {{
      "type": "Vulnerability Type Name",
      "swc_id": "SWC-XXX",
      "severity": "High or Medium or Low",
      "location": "function_name() at line X",
      "description": "Brief explanation"
    }}
  ],
  "vulnerabilities": [
    {{
      "type": "Vulnerability Type Name",
      "swc_id": "SWC-XXX",
      "severity": "Critical or High or Medium or Low",
      "location": "function_name() at line X",
      "description": "Clear explanation of the vulnerability",
      "exploit_scenario": "Step-by-step how an attacker could exploit this",
      "recommendation": "Specific fix recommendation"
    }}
  ],
  "reasoning": "Your step-by-step Chain-of-Thought analysis covering all 3 vulnerability checks above"
}}

If no vulnerabilities found, return:
{{
  "verdict": "SAFE",
  "confidence": "HIGH",
  "primary_vulnerability": null,
  "secondary_warnings": [],
  "vulnerabilities": [],
  "reasoning": "Explanation of why code is safe, referencing each check"
}}

## CRITICAL RULES:
1. Output ONLY valid JSON - no markdown, no code blocks, no extra text before or after
2. Check ALL 3 types systematically - DO NOT skip any
3. ONLY report Reentrancy (SWC-107), Integer Overflow/Underflow (SWC-101), or Unchecked Return Value (SWC-104). Do NOT report ANY other SWC types (e.g., SWC-133, SWC-106, SWC-115, etc.) — they are OUT OF SCOPE
4. If ALL 3 checks above are NO → verdict MUST be "SAFE". Do NOT override this with Slither findings or other vulnerability types. Slither is context only — your job is to check the 3 types above
5. STRICT EVIDENCE REQUIRED - only report a vulnerability if you can describe a concrete exploit scenario
6. .send() and .transfer() forward only 2300 gas — they CANNOT cause reentrancy. Do NOT report SWC-107 for .send()/.transfer()
7. Integer Overflow: ONLY report if the overflow can be EXPLOITED (affects balance, supply, auth). Do NOT report for counters, timestamps, or non-critical arithmetic
8. If SafeMath is used or Solidity >= 0.8.0 → Integer Overflow is NOT vulnerable
9. If ReentrancyGuard/nonReentrant is used → Reentrancy is NOT vulnerable
10. If return value is checked with require() or if() → Unchecked Return Value is NOT vulnerable
11. primary_vulnerability = the SINGLE most dangerous finding. secondary_warnings = other lesser findings
12. Do NOT "report just to be safe" — only report what you can PROVE with evidence from the code

## SEVERITY CONTEXT RULES (for secondary findings):
- A vulnerability that EXISTS but has LIMITED exploit impact → downgrade severity:
  - Integer Overflow on a multiply that has bounded inputs (e.g., price * small_quantity) → Medium or Low, not High
  - Unchecked .send() that only affects refund of excess payment (not main balance) → Medium, not High
  - Reentrancy where the re-enterable amount is capped or negligible → Medium, not Critical
- A vulnerability with FULL exploit impact (can drain funds, mint unlimited tokens, bypass auth) → keep High or Critical
- If a secondary finding has severity Low → consider NOT reporting it (noise reduction)

Now begin your systematic analysis and output JSON.
"""
    return prompt


def parse_json_response(text: str) -> dict:
    """Parse JSON from LLM response"""
    if not text:
        return None
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def filter_out_of_scope(analysis_json: dict) -> dict:
    """Filter out non-target SWC types"""
    if not analysis_json:
        return analysis_json

    primary = analysis_json.get("primary_vulnerability")
    if primary and primary.get("swc_id") not in ALLOWED_SWCS:
        analysis_json["primary_vulnerability"] = None

    secondaries = analysis_json.get("secondary_warnings", [])
    analysis_json["secondary_warnings"] = [s for s in secondaries if s.get("swc_id") in ALLOWED_SWCS]

    vulns = analysis_json.get("vulnerabilities", [])
    analysis_json["vulnerabilities"] = [v for v in vulns if v.get("swc_id") in ALLOWED_SWCS]

    if not analysis_json.get("primary_vulnerability") and not analysis_json.get("vulnerabilities"):
        if analysis_json.get("verdict") == "VULNERABLE":
            analysis_json["verdict"] = "SAFE"

    return analysis_json


def filter_pragma_080(analysis_json: dict, pragma: str) -> dict:
    """Filter SWC-101 for Solidity >= 0.8.0"""
    if not analysis_json:
        return analysis_json

    ver_match = re.search(r'0\.(\d+)', pragma)
    if not ver_match:
        return analysis_json

    minor = int(ver_match.group(1))
    if minor < 8:
        return analysis_json

    # Solidity >= 0.8.0: remove SWC-101
    primary = analysis_json.get("primary_vulnerability")
    if primary and primary.get("swc_id") == "SWC-101":
        analysis_json["primary_vulnerability"] = None

    analysis_json["secondary_warnings"] = [
        s for s in analysis_json.get("secondary_warnings", [])
        if s.get("swc_id") != "SWC-101"
    ]
    analysis_json["vulnerabilities"] = [
        v for v in analysis_json.get("vulnerabilities", [])
        if v.get("swc_id") != "SWC-101"
    ]

    if not analysis_json.get("primary_vulnerability") and not analysis_json.get("vulnerabilities"):
        if analysis_json.get("verdict") == "VULNERABLE":
            analysis_json["verdict"] = "SAFE"

    return analysis_json


def analyze_with_llm_only(code: str, client) -> dict:
    """Send code directly to Gemini (no Slither, no RAG)"""
    prompt = create_only_llm_prompt(code)
    system_prefix = "You are an expert blockchain security auditor. Output ONLY valid JSON.\n\n"
    full_prompt = system_prefix + prompt

    for attempt in range(3):
        try:
            if attempt > 0:
                wait_time = 20 * (2 ** (attempt - 1))
                print(f"    [RETRY] Attempt {attempt + 1}/3 after {wait_time}s...")
                time.sleep(wait_time)

            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=full_prompt
            )
            text = response.text
            analysis_json = parse_json_response(text)
            if analysis_json:
                analysis_json = filter_out_of_scope(analysis_json)
            return {"success": True, "analysis_json": analysis_json, "raw": text}

        except Exception as e:
            error_msg = str(e)
            print(f"    Error: {error_msg[:100]}")
            if attempt < 2 and ("429" in error_msg or "rate" in error_msg.lower()):
                continue
            if attempt < 2:
                continue
            return {"success": False, "error": error_msg}

    return {"success": False, "error": "Max retries exceeded"}


def discover_contracts():
    """Scan dataset directory for single-file .sol contracts"""
    contracts = []
    skipped_empty = 0
    skipped_multi = 0

    for project_dir in sorted(DATASET_DIR.iterdir()):
        if not project_dir.is_dir() or not project_dir.name.startswith("0x"):
            continue

        sol_files = list(project_dir.rglob("*.sol"))

        if len(sol_files) != 1:
            skipped_multi += 1
            continue

        sol_file = sol_files[0]
        try:
            size = sol_file.stat().st_size
            if size < 10:
                skipped_empty += 1
                continue

            with open(sol_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = len(content.strip().splitlines())

            if lines < MIN_FILE_LINES:
                skipped_empty += 1
                continue

            pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
            pragma = pragma_match.group(1).strip() if pragma_match else "unknown"

            chain = project_dir.name.split("_")[-1] if "_" in project_dir.name else "unknown"

            contracts.append({
                "project": project_dir.name,
                "file": str(sol_file.relative_to(DATASET_DIR)),
                "filepath": str(sol_file),
                "filename": sol_file.name,
                "lines": lines,
                "bytes": size,
                "pragma": pragma,
                "chain": chain,
            })
        except Exception as e:
            print(f"  Warning: Could not read {sol_file}: {e}")
            continue

    print(f"Discovered: {len(contracts)} valid single-file contracts")
    print(f"Skipped: {skipped_empty} empty/tiny, {skipped_multi} multi-file")
    return contracts


def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    return {"completed": {}, "results": []}


def save_checkpoint(checkpoint):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(checkpoint, f, indent=2)


def run_evaluation(resume=False):
    contracts = discover_contracts()
    total = len(contracts)

    if total == 0:
        print("No contracts found! Check DATASET_DIR path.")
        return

    print(f"\n{'='*70}")
    print(f"ABLATION STUDY: LLM Only (No Slither, No RAG) — Top200")
    print(f"{'='*70}")
    print(f"Model: {MODEL_NAME}")
    print(f"Total contracts: {total}")
    print(f"Expected verdict: ALL SAFE")
    print(f"{'='*70}\n")

    client = genai.Client(api_key=API_KEY)

    if resume:
        checkpoint = load_checkpoint()
        done_count = len(checkpoint['completed'])
        print(f"Resuming from checkpoint: {done_count}/{total} already done\n")
    else:
        checkpoint = {"completed": {}, "results": []}

    start_time = time.time()

    for i, contract in enumerate(contracts):
        filepath = contract["filepath"]
        project = contract["project"]

        if project in checkpoint["completed"]:
            continue

        print(f"[{i+1}/{total}] {contract['filename']} ({contract['lines']} lines, {contract['chain']})...", end=" ", flush=True)

        t0 = time.time()

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()

            result = analyze_with_llm_only(code, client)
            elapsed = time.time() - t0

            if not result["success"]:
                print(f"ERROR ({elapsed:.1f}s): {result.get('error', '')[:80]}")
                entry = {
                    "project": project,
                    "file": contract["file"],
                    "filename": contract["filename"],
                    "expected": "SAFE",
                    "predicted_verdict": "ERROR",
                    "is_correct": False,
                    "is_false_positive": False,
                    "detected_types": [],
                    "analysis_time": round(elapsed, 1),
                    "lines": contract["lines"],
                    "pragma": contract["pragma"],
                    "chain": contract["chain"],
                    "error": result.get("error", "")
                }
            else:
                analysis_json = result["analysis_json"]

                # Apply pragma filter
                if analysis_json:
                    analysis_json = filter_pragma_080(analysis_json, contract["pragma"])

                verdict = "UNKNOWN"
                detected_types = []

                if analysis_json:
                    verdict = analysis_json.get("verdict", "UNKNOWN").upper()
                    if verdict not in ["VULNERABLE", "SAFE"]:
                        verdict = "UNKNOWN"

                    # Extract detected types
                    primary = analysis_json.get("primary_vulnerability")
                    if primary and isinstance(primary, dict):
                        detected_types.append({
                            "type": primary.get("type", "Unknown"),
                            "swc_id": primary.get("swc_id", "N/A")
                        })
                    for vuln in analysis_json.get("vulnerabilities", []):
                        vtype = vuln.get("type", "")
                        swc = vuln.get("swc_id", "")
                        if vtype and not any(d["swc_id"] == swc for d in detected_types):
                            detected_types.append({"type": vtype, "swc_id": swc})

                is_correct = verdict == "SAFE"
                is_fp = verdict == "VULNERABLE"
                status = "CORRECT" if is_correct else ("FP!" if is_fp else verdict)

                print(f"{verdict} ({elapsed:.1f}s) [{status}]")
                if detected_types:
                    for dt in detected_types:
                        print(f"   -> FP: {dt['type']} ({dt['swc_id']})")

                entry = {
                    "project": project,
                    "file": contract["file"],
                    "filename": contract["filename"],
                    "expected": "SAFE",
                    "predicted_verdict": verdict,
                    "is_correct": is_correct,
                    "is_false_positive": is_fp,
                    "detected_types": detected_types,
                    "analysis_time": round(elapsed, 1),
                    "lines": contract["lines"],
                    "pragma": contract["pragma"],
                    "chain": contract["chain"],
                }

        except Exception as e:
            elapsed = time.time() - t0
            print(f"EXCEPTION ({elapsed:.1f}s): {e}")
            entry = {
                "project": project,
                "file": contract["file"],
                "filename": contract["filename"],
                "expected": "SAFE",
                "predicted_verdict": "ERROR",
                "is_correct": False,
                "is_false_positive": False,
                "detected_types": [],
                "analysis_time": round(elapsed, 1),
                "lines": contract["lines"],
                "pragma": contract["pragma"],
                "chain": contract["chain"],
                "error": str(e)
            }

        checkpoint["results"].append(entry)
        checkpoint["completed"][project] = True
        save_checkpoint(checkpoint)

        if i < total - 1:
            time.sleep(DELAY_BETWEEN_CALLS)

    total_time = time.time() - start_time

    # === COMPUTE METRICS ===
    results = checkpoint["results"]
    n_total = len(results)
    n_correct = sum(1 for r in results if r["is_correct"])
    n_fp = sum(1 for r in results if r["is_false_positive"])
    n_error = sum(1 for r in results if r["predicted_verdict"] == "ERROR")
    n_unknown = sum(1 for r in results if r["predicted_verdict"] == "UNKNOWN")

    # Per-chain
    chains = {}
    for r in results:
        chain = r["chain"]
        if chain not in chains:
            chains[chain] = {"total": 0, "correct": 0, "fp": 0, "error": 0}
        chains[chain]["total"] += 1
        if r["is_correct"]:
            chains[chain]["correct"] += 1
        if r["is_false_positive"]:
            chains[chain]["fp"] += 1
        if r["predicted_verdict"] == "ERROR":
            chains[chain]["error"] += 1

    # Per-pragma
    pragma_groups = {}
    for r in results:
        pragma = r["pragma"]
        ver_match = re.search(r'0\.(\d+)', pragma)
        if ver_match:
            group = f"0.{ver_match.group(1)}.x"
        else:
            group = "unknown"
        if group not in pragma_groups:
            pragma_groups[group] = {"total": 0, "correct": 0, "fp": 0}
        pragma_groups[group]["total"] += 1
        if r["is_correct"]:
            pragma_groups[group]["correct"] += 1
        if r["is_false_positive"]:
            pragma_groups[group]["fp"] += 1

    # FP type breakdown
    fp_types = {}
    for r in results:
        if r["is_false_positive"]:
            for dt in r["detected_types"]:
                key = dt.get("type", "Unknown")
                if key not in fp_types:
                    fp_types[key] = []
                fp_types[key].append(f"{r['filename']} ({r['project']})")

    avg_time = sum(r["analysis_time"] for r in results) / max(n_total, 1)

    # === PRINT RESULTS ===
    print(f"\n{'='*70}")
    print(f"PART 1 — FALSE POSITIVE RESULTS (LLM Only)")
    print(f"{'='*70}\n")
    print(f"All contracts are SAFE (production DeFi, audited):")
    print(f"  Correctly identified SAFE:  {n_correct}/{n_total}")
    print(f"  False Positives (FP):       {n_fp}/{n_total}")
    if n_error:
        print(f"  Errors:                     {n_error}/{n_total}")
    if n_unknown:
        print(f"  Unknown:                    {n_unknown}/{n_total}")
    print()
    print(f"  Specificity (True Negative Rate): {n_correct/max(n_total,1)*100:.1f}%")
    print(f"  False Positive Rate:              {n_fp/max(n_total,1)*100:.1f}%")
    print()
    print(f"Avg Analysis Time: {avg_time:.1f}s")
    print(f"Total Time: {total_time/60:.1f} min")

    print(f"\n{'='*70}")
    print(f"PART 2 — PER-CHAIN BREAKDOWN")
    print(f"{'='*70}")
    for chain in sorted(chains.keys()):
        stats = chains[chain]
        pct = stats["correct"] / max(stats["total"], 1) * 100
        print(f"  {chain:10s}: {stats['correct']}/{stats['total']} correct ({pct:.0f}%), {stats['fp']} FP, {stats['error']} errors")

    print(f"\n{'='*70}")
    print(f"PART 3 — PER-PRAGMA VERSION BREAKDOWN")
    print(f"{'='*70}")
    for group in sorted(pragma_groups.keys()):
        stats = pragma_groups[group]
        pct = stats["correct"] / max(stats["total"], 1) * 100
        fpr = stats["fp"] / max(stats["total"], 1) * 100
        print(f"  {group:10s}: {stats['total']:3d} contracts, {stats['correct']}/{stats['total']} correct ({pct:.0f}%), FPR: {fpr:.0f}%")

    if fp_types:
        print(f"\n{'='*70}")
        print(f"PART 4 — FALSE POSITIVE DETAILS")
        print(f"{'='*70}")
        for fp_type, files in sorted(fp_types.items()):
            print(f"\n    {fp_type} — {len(files)} false positives:")
            for f in files[:20]:
                print(f"      {f}")
            if len(files) > 20:
                print(f"      ... and {len(files)-20} more")

    # === COMPARISON TABLE ===
    print(f"\n{'='*70}")
    print(f"COMPARISON: LLM Only vs Full Pipeline (Top200)")
    print(f"{'='*70}")
    print()
    print("| Configuration | Correct | FP | FPR | Specificity |")
    print("|---------------|---------|----|----|-------------|")
    print(f"| LLM Only (no Slither, no RAG) | {n_correct}/{n_total} | {n_fp} | {n_fp/max(n_total,1)*100:.1f}% | {n_correct/max(n_total,1)*100:.1f}% |")
    print(f"| Full Pipeline (reference)     | 192/225 | 33 | 14.7% | 85.3% |")

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Configuration:        LLM Only (no Slither, no RAG)")
    print(f"  Model:                {MODEL_NAME}")
    print(f"  Dataset:              GPTScan Top200 ({n_total} single-file contracts)")
    print(f"  Specificity:          {n_correct}/{n_total} = {n_correct/max(n_total,1)*100:.1f}%")
    print(f"  False Positive Rate:  {n_fp}/{n_total} = {n_fp/max(n_total,1)*100:.1f}%")
    if n_error:
        print(f"  Errors:               {n_error}/{n_total}")
    print(f"  Avg Analysis Time:    {avg_time:.1f}s")
    print(f"  Total Time:           {total_time/60:.1f} min")
    print(f"{'='*70}")

    # === SAVE RESULTS ===
    output = {
        "metadata": {
            "evaluation": "Ablation Study - LLM Only",
            "configuration": "Only LLM (no Slither, no RAG)",
            "model": MODEL_NAME,
            "timestamp": datetime.now().isoformat(),
            "dataset": "GPTScan Top200 (Production DeFi Contracts)",
            "total_contracts": n_total,
            "ground_truth": "ALL SAFE (production-deployed, audited)",
        },
        "metrics": {
            "total": n_total,
            "correct_safe": n_correct,
            "false_positives": n_fp,
            "errors": n_error,
            "unknown": n_unknown,
            "specificity": round(n_correct / max(n_total, 1), 4),
            "false_positive_rate": round(n_fp / max(n_total, 1), 4),
            "avg_analysis_time": round(avg_time, 1),
            "total_time_min": round(total_time / 60, 1),
        },
        "per_chain": chains,
        "per_pragma": pragma_groups,
        "false_positive_types": {k: len(v) for k, v in fp_types.items()},
        "false_positive_details": fp_types,
        "results": results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {OUTPUT_FILE}")

    # Clean up checkpoint
    if CHECKPOINT_FILE.exists():
        CHECKPOINT_FILE.unlink()
        print("Checkpoint cleaned up (evaluation complete)")

    print(f"{'='*70}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DarkHotel Ablation: LLM Only on Top200")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    args = parser.parse_args()

    run_evaluation(resume=args.resume)
