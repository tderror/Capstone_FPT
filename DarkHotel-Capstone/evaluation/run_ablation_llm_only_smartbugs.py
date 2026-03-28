"""
DarkHotel Ablation Study - LLM Only on SmartBugs-Curated
Sends raw Solidity code directly to Gemini (no Slither, no RAG).
Measures Recall when LLM works alone on 98 vulnerable contracts.

Categories:
  - Reentrancy (SWC-107): 31 contracts
  - Integer Overflow/Underflow (SWC-101): 15 contracts
  - Unchecked Return Value (SWC-104): 52 contracts

Usage:
    cd evaluation && python run_ablation_llm_only_smartbugs.py
    Resume:  python run_ablation_llm_only_smartbugs.py --resume
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

GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
GOOGLE_CLOUD_LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-pro")

# Set Google Application Credentials for Vertex AI
_gac = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if _gac:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = _gac

if not GOOGLE_CLOUD_PROJECT:
    print("ERROR: No project found. Set GOOGLE_CLOUD_PROJECT in backend/.env")
    sys.exit(1)

from google import genai
from google.genai.types import HttpOptions

# --- CONFIG ---
DATASET_DIR = Path(__file__).parent / "external_datasets" / "SmartBugs-Curated" / "dataset"
MAPPING_FILE = Path(__file__).parent / "smartbugs_ground_truth.json"
OUTPUT_FILE = Path(__file__).parent / "ablation_llm_only_smartbugs_results.json"
CHECKPOINT_FILE = Path(__file__).parent / "ablation_llm_only_smartbugs_checkpoint.json"

DELAY_BETWEEN_CALLS = 3
ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}


def create_only_llm_prompt(code: str) -> str:
    """Tier 1 only prompt — matches what full pipeline LLM sees when CRAG=INCORRECT.

    NO expert rules (safe pattern recognition, severity calibration) — those come
    from RAG Tier 2. This creates a fair ablation comparison:
    - LLM-only: Tier 1 basic detection → higher FP rate
    - Full pipeline: Tier 1 + Tier 2 expert rules → lower FP rate
    """

    prompt = f"""You are an expert blockchain security auditor. Your task is to SYSTEMATICALLY check the Solidity code for the following 3 vulnerability types.

## STATIC ANALYSIS (Slither):
- No Slither analysis available

## HISTORICAL CASES:
No similar cases found in the audit knowledge base.
You have NO expert rules from historical audits — rely entirely on your own analysis.
Be CONSERVATIVE: only report vulnerabilities you are highly confident about.

## CODE TO ANALYZE:
```solidity
{code}
```

## VULNERABILITY CHECKLIST (Tier 1 — Basic Detection):

You MUST check ALL 3 vulnerability types below. For EACH type, explicitly state YES or NO with evidence.

### 1. REENTRANCY (SWC-107)
- Check: Are there external calls BEFORE state updates?
- VULNERABLE: State changes happen AFTER external calls (`.call{{value:}}()`)
- Answer: [YES/NO] with evidence

### 2. INTEGER OVERFLOW/UNDERFLOW (SWC-101)
- Check: What is the pragma solidity version? Are there unprotected arithmetic operations?
- VULNERABLE: Solidity < 0.8.0 + no SafeMath + arithmetic affects critical values
- Answer: [YES/NO] with evidence

### 3. UNCHECKED RETURN VALUE (SWC-104)
- Check: Are low-level calls used without checking the return value?
- VULNERABLE: `.send()` or `.call()` without `require()` or `if()` check
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

## RULES:
1. Output ONLY valid JSON - no markdown, no code blocks, no extra text
2. Check ALL 3 types systematically - DO NOT skip any
3. ONLY report SWC-107, SWC-101, or SWC-104. All other SWC types are OUT OF SCOPE
4. If ALL 3 checks are NO → verdict MUST be "SAFE"
5. STRICT EVIDENCE REQUIRED - only report with a concrete exploit scenario
6. primary_vulnerability = SINGLE most dangerous finding. secondary_warnings = lesser findings
7. Do NOT "report just to be safe" — only report what you can PROVE with evidence

Now begin your systematic analysis and output JSON.
"""
    return prompt


def parse_json_response(text: str) -> dict:
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


def analyze_with_llm_only(code: str, client) -> dict:
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
            if attempt < 2:
                continue
            return {"success": False, "error": error_msg}

    return {"success": False, "error": "Max retries exceeded"}


def normalize_swc(swc_id: str) -> str:
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    if match:
        return f"SWC-{match.group(1)}"
    return swc_id


def extract_detected_swcs(analysis_json: dict) -> list:
    if not analysis_json:
        return []
    swcs = []
    primary = analysis_json.get("primary_vulnerability")
    if primary and isinstance(primary, dict):
        swc = normalize_swc(primary.get("swc_id", ""))
        if swc:
            swcs.append(swc)
    for warn in analysis_json.get("secondary_warnings", []):
        if isinstance(warn, dict):
            swc = normalize_swc(warn.get("swc_id", ""))
            if swc and swc not in swcs:
                swcs.append(swc)
    if not swcs:
        for vuln in analysis_json.get("vulnerabilities", []):
            swc = normalize_swc(vuln.get("swc_id", ""))
            if swc and swc not in swcs:
                swcs.append(swc)
    return swcs


def extract_detected_types(analysis_json: dict) -> list:
    if not analysis_json:
        return []
    types = []
    for vuln in analysis_json.get("vulnerabilities", []):
        vtype = vuln.get("type", "")
        swc = vuln.get("swc_id", "")
        if vtype:
            types.append({"type": vtype, "swc_id": swc})
    primary = analysis_json.get("primary_vulnerability")
    if primary and isinstance(primary, dict):
        ptype = primary.get("type", "")
        pswc = primary.get("swc_id", "")
        if ptype and not any(t["swc_id"] == pswc for t in types):
            types.insert(0, {"type": ptype, "swc_id": pswc})
    return types


def load_ground_truth():
    with open(MAPPING_FILE, "r") as f:
        data = json.load(f)
    return data["contracts"]


def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    return {"results": [], "evaluated_files": []}


def save_checkpoint(results, evaluated_files):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({
            "results": results,
            "evaluated_files": evaluated_files,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)


# ============================================================
# SECONDARY FINDINGS VERIFICATION (same as smartbugs eval)
# ============================================================

def read_contract(filepath: Path) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def get_solidity_version(code: str) -> float:
    match = re.search(r'pragma\s+solidity\s+[\^~>=]*(\d+\.\d+)', code)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return 0.0
    return 0.0


def has_safemath(code: str) -> bool:
    return bool(re.search(r'(SafeMath|using\s+SafeMath)', code))


def has_call_value(code: str) -> bool:
    return bool(re.search(r'\.(call\s*\{|call\.value\s*\()', code))


def has_unchecked_send_or_call(code: str) -> bool:
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if '.send(' in stripped:
            if not re.search(r'(require|if)\s*\(.*\.send\(', stripped):
                if not re.search(r'(bool\s+\w+|success)\s*=', stripped):
                    return True
        if '.call(' in stripped or '.call{' in stripped or '.call.value(' in stripped:
            if not re.search(r'(require|if)\s*\(.*\.(call|call\.value)', stripped):
                if not re.search(r'(bool\s+\w+|success)\s*[\,\)]\s*=', stripped):
                    found_check = False
                    for j in range(i, min(i + 3, len(lines))):
                        if re.search(r'require\s*\(\s*(success|\w+)\s*\)', lines[j]):
                            found_check = True
                            break
                    if not found_check:
                        return True
    return False


def verify_secondary(swc_id: str, code: str) -> bool:
    if swc_id == "SWC-107":
        return has_call_value(code)
    elif swc_id == "SWC-101":
        version = get_solidity_version(code)
        if version >= 0.8:
            return False
        if has_safemath(code):
            return False
        return bool(re.search(r'[\+\-\*]', code))
    elif swc_id == "SWC-104":
        return has_unchecked_send_or_call(code)
    return False


def get_false_alarm_reason(swc_id: str, code: str) -> str:
    if swc_id == "SWC-107":
        if not has_call_value(code):
            return "No .call{value:}() — only .send()/.transfer() (2300 gas)"
        return "Unknown"
    elif swc_id == "SWC-101":
        if get_solidity_version(code) >= 0.8:
            return f"Solidity {get_solidity_version(code)} has built-in overflow protection"
        if has_safemath(code):
            return "SafeMath is used"
        return "No exploitable arithmetic"
    elif swc_id == "SWC-104":
        return "Return values are checked"
    return "Outside target SWC types"


def analyze_secondary(results: list):
    type_recall = {
        "SWC-107": {"label": "Reentrancy", "total": 0, "detected": 0},
        "SWC-101": {"label": "Integer Overflow/Underflow", "total": 0, "detected": 0},
        "SWC-104": {"label": "Unchecked Return Value", "total": 0, "detected": 0}
    }

    secondary_stats = {
        "total": 0, "verified_true": 0, "false_alarm": 0, "details": []
    }
    primary_miss = []

    for r in results:
        expected_swc = normalize_swc(r["expected_swc"])
        predicted_swcs = [normalize_swc(t.get("swc_id", "")) for t in r.get("predicted_types", [])]

        if expected_swc in type_recall:
            type_recall[expected_swc]["total"] += 1
            if expected_swc in predicted_swcs:
                type_recall[expected_swc]["detected"] += 1
            else:
                primary_miss.append(r)

        secondary_swcs = list(set(s for s in predicted_swcs if s and s != expected_swc))
        if secondary_swcs:
            sol_file = DATASET_DIR / r["file"]
            code = read_contract(sol_file)

            for sec_swc in secondary_swcs:
                secondary_stats["total"] += 1
                is_valid = verify_secondary(sec_swc, code) if code else False

                if is_valid:
                    secondary_stats["verified_true"] += 1
                else:
                    secondary_stats["false_alarm"] += 1
                    secondary_stats["details"].append({
                        "file": r["filename"],
                        "expected": expected_swc,
                        "false_alarm_swc": sec_swc,
                        "reason": get_false_alarm_reason(sec_swc, code)
                    })

    return type_recall, secondary_stats, primary_miss


# ============================================================
# MAIN
# ============================================================

def run_evaluation(resume=False):
    print("=" * 70)
    print("ABLATION STUDY: LLM Only (No Slither, No RAG) — SmartBugs")
    print(f"Model: {MODEL_NAME}")
    print("=" * 70)

    ground_truth = load_ground_truth()
    total = len(ground_truth)
    print(f"\nContracts to evaluate: {total}")

    type_counts = {}
    for v in ground_truth.values():
        t = v["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")
    print("-" * 70)

    client = genai.Client(
        http_options=HttpOptions(api_version="v1beta1"),
        vertexai=True,
        project=GOOGLE_CLOUD_PROJECT,
        location=GOOGLE_CLOUD_LOCATION,
    )

    results = []
    evaluated_files = []
    if resume:
        checkpoint = load_checkpoint()
        results = checkpoint.get("results", [])
        evaluated_files = checkpoint.get("evaluated_files", [])
        if evaluated_files:
            print(f"\nResuming from checkpoint: {len(evaluated_files)} already evaluated")

    errors = []
    start_time = time.time()

    for i, (rel_path, truth) in enumerate(ground_truth.items(), 1):
        if rel_path in evaluated_files:
            continue

        filepath = DATASET_DIR / rel_path

        if not filepath.exists():
            print(f"[{i}/{total}] SKIP (not found): {rel_path}")
            errors.append({"file": rel_path, "error": "File not found"})
            continue

        print(f"\n[{i}/{total}] {filepath.name}")
        print(f"  Expected: VULNERABLE ({truth['type']} - {truth['swc_id']})")

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()

            t0 = time.time()
            response = analyze_with_llm_only(code, client)
            elapsed = time.time() - t0

            if not response["success"]:
                print(f"  ERROR: {response.get('error', '')[:100]}")
                errors.append({"file": rel_path, "error": response.get("error", "")})
                continue

            analysis_json = response["analysis_json"]
            verdict = "UNKNOWN"
            detected_swcs = []
            detected_types = []

            if analysis_json:
                verdict = analysis_json.get("verdict", "UNKNOWN").upper()
                if verdict not in ["VULNERABLE", "SAFE"]:
                    verdict = "UNKNOWN"
                detected_swcs = extract_detected_swcs(analysis_json)
                detected_types = extract_detected_types(analysis_json)

            correct = (verdict == "VULNERABLE")
            type_match = truth["swc_id"] in detected_swcs
            status = "TP" if correct else "FN"
            swc_match = "MATCHED" if type_match else "NOT MATCHED"

            print(f"  Predicted: {verdict} | {status} | {truth['swc_id']} {swc_match} | {elapsed:.1f}s")
            if detected_types:
                for dt in detected_types:
                    sev = dt.get("severity", "")
                    loc = dt.get("location", "")
                    print(f"    - {dt['type']} ({dt['swc_id']}){f' [{sev}]' if sev else ''}{f' {loc}' if loc else ''}")

            result = {
                "file": rel_path,
                "filename": filepath.name,
                "expected_type": truth["type"],
                "expected_swc": truth["swc_id"],
                "predicted_verdict": verdict,
                "predicted_types": detected_types,
                "predicted_swcs": detected_swcs,
                "type_match": type_match,
                "correct": correct,
                "time_seconds": round(elapsed, 1)
            }
            results.append(result)
            evaluated_files.append(rel_path)
            save_checkpoint(results, evaluated_files)

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            errors.append({"file": rel_path, "error": str(e)})

        if i < total:
            time.sleep(DELAY_BETWEEN_CALLS)

    total_time = time.time() - start_time

    # ============================================================
    # PART 1: Basic Metrics
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 1 — DETECTION RESULTS (LLM Only)")
    print("=" * 70)

    tp = sum(1 for r in results if r["correct"])
    fn = sum(1 for r in results if not r["correct"])
    type_matches = sum(1 for r in results if r.get("type_match"))
    n_total = len(results)

    recall = tp / n_total if n_total > 0 else 0
    type_accuracy = type_matches / n_total if n_total > 0 else 0

    print(f"\nDetection (all contracts are vulnerable):")
    print(f"  Detected (TP):  {tp}/{n_total}")
    print(f"  Missed (FN):    {fn}/{n_total}")
    print(f"\n  Recall (Detection Rate): {recall:.2%}")
    print(f"  Type Accuracy:           {type_accuracy:.2%}")

    # Per-category
    print(f"\nPer-Category Breakdown:")
    categories = {}
    for r in results:
        cat = r["expected_type"]
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0, "type_match": 0}
        categories[cat]["total"] += 1
        if r["correct"]:
            categories[cat]["detected"] += 1
        if r.get("type_match"):
            categories[cat]["type_match"] += 1

    for cat, stats in sorted(categories.items()):
        det_rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        type_rate = stats["type_match"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {cat:30s}: {stats['detected']}/{stats['total']} detected ({det_rate:.0%}), "
              f"type match: {stats['type_match']}/{stats['total']} ({type_rate:.0%})")

    times = [r["time_seconds"] for r in results]
    if times:
        print(f"\nAvg Analysis Time: {sum(times)/len(times):.1f}s")
        print(f"Total Time: {sum(times)/60:.1f} min")

    # ============================================================
    # PART 2: Per-Type Recall
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 2 — PER-TYPE RECALL")
    print("=" * 70)

    type_recall, secondary_stats, primary_miss = analyze_secondary(results)

    for swc, stats in type_recall.items():
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {stats['label']:35s} ({swc}): {stats['detected']}/{stats['total']} = {rate:.0%}")

    total_detected = sum(s["detected"] for s in type_recall.values())
    total_all = sum(s["total"] for s in type_recall.values())
    if total_all > 0:
        print(f"  {'Overall':35s}       : {total_detected}/{total_all} = {total_detected/total_all:.0%}")

    if primary_miss:
        print(f"\n  MISSED contracts:")
        for m in primary_miss:
            swcs = [t.get("swc_id", "") for t in m.get("predicted_types", [])]
            print(f"    {m['filename']} — expected {m['expected_swc']}, got {swcs}")

    # ============================================================
    # PART 3: Secondary Analysis
    # ============================================================
    print(f"\n{'='*70}")
    print("PART 3 — SECONDARY FINDINGS ANALYSIS")
    print(f"{'='*70}")
    print(f"  Total secondary findings: {secondary_stats['total']}")
    print(f"  Verified real:            {secondary_stats['verified_true']}")
    print(f"  False alarms:             {secondary_stats['false_alarm']}")

    if secondary_stats['total'] > 0:
        true_rate = secondary_stats['verified_true'] / secondary_stats['total']
        false_rate = secondary_stats['false_alarm'] / secondary_stats['total']
        print(f"\n  Verified real rate:  {true_rate:.1%}")
        print(f"  False alarm rate:   {false_rate:.1%}")

    if secondary_stats["details"]:
        print(f"\n  False alarm details:")
        by_swc = {}
        for d in secondary_stats["details"]:
            swc = d["false_alarm_swc"]
            if swc not in by_swc:
                by_swc[swc] = []
            by_swc[swc].append(d)

        for swc, items in sorted(by_swc.items()):
            swc_label = {"SWC-107": "Reentrancy", "SWC-101": "Integer Overflow",
                         "SWC-104": "Unchecked Return Value"}.get(swc, swc)
            print(f"\n    {swc_label} ({swc}) — {len(items)} false alarms:")
            for item in items[:5]:
                print(f"      {item['file']}: {item['reason']}")
            if len(items) > 5:
                print(f"      ... and {len(items) - 5} more")

    # ============================================================
    # COMPARISON TABLE
    # ============================================================
    print(f"\n{'='*70}")
    print("COMPARISON: LLM Only vs Full Pipeline (SmartBugs)")
    print(f"{'='*70}")
    print()
    print("| Configuration | TP | FN | Recall | Type Accuracy |")
    print("|---------------|----|----|--------|---------------|")
    print(f"| LLM Only (no Slither, no RAG) | {tp} | {fn} | {recall:.2%} | {type_accuracy:.2%} |")
    print(f"| Full Pipeline (reference)     | 97 | 1  | 98.98% | 97.96% |")

    # ============================================================
    # SUMMARY
    # ============================================================
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"  Configuration:        LLM Only (no Slither, no RAG)")
    print(f"  Model:                {MODEL_NAME}")
    print(f"  Primary Recall:       {total_detected}/{total_all} = {total_detected/total_all:.0%}" if total_all > 0 else "")
    if secondary_stats['total'] > 0:
        print(f"  Secondary Accuracy:   {secondary_stats['verified_true']}/{secondary_stats['total']} verified real "
              f"({secondary_stats['verified_true']/secondary_stats['total']:.0%})")
        print(f"  False Alarm Rate:     {secondary_stats['false_alarm']}/{secondary_stats['total']} "
              f"({secondary_stats['false_alarm']/secondary_stats['total']:.0%})")
    print(f"  Avg Analysis Time:    {sum(times)/len(times):.1f}s" if times else "")
    print(f"  Total Time:           {total_time/60:.1f} min")
    print(f"{'='*70}")

    # Save results
    output = {
        "metadata": {
            "evaluation": "Ablation Study - LLM Only",
            "configuration": "Only LLM (no Slither, no RAG)",
            "model": MODEL_NAME,
            "timestamp": datetime.now().isoformat(),
            "dataset": "SmartBugs-Curated",
            "total_contracts": total,
            "evaluated": len(results),
            "errors": len(errors),
        },
        "metrics": {
            "tp": tp,
            "fn": fn,
            "total": n_total,
            "recall": round(recall, 4),
            "type_accuracy": round(type_accuracy, 4),
        },
        "per_category": categories,
        "per_type_recall": {swc: {
            "label": s["label"], "detected": s["detected"],
            "total": s["total"],
            "recall": round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0
        } for swc, s in type_recall.items()},
        "secondary_analysis": {
            "total": secondary_stats["total"],
            "verified_true": secondary_stats["verified_true"],
            "false_alarm": secondary_stats["false_alarm"],
            "false_alarm_details": secondary_stats["details"]
        },
        "results": results,
        "errors": errors
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {OUTPUT_FILE}")

    if len(evaluated_files) >= total and CHECKPOINT_FILE.exists():
        CHECKPOINT_FILE.unlink()
        print("Checkpoint cleaned up (evaluation complete)")

    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DarkHotel Ablation: LLM Only on SmartBugs")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    args = parser.parse_args()

    run_evaluation(resume=args.resume)
