"""
DarkHotel Evaluation - SmartBugs-Curated Dataset
Runs the full 6-step pipeline on 98 vulnerable contracts from SmartBugs-Curated,
then automatically analyzes per-type metrics and false alarm rate.

Categories:
  - Reentrancy (SWC-107): 31 contracts
  - Integer Overflow/Underflow (SWC-101): 15 contracts
  - Unchecked Return Value (SWC-104): 52 contracts

Usage:
    1. Start backend: cd backend && uvicorn main:app --port 8000
    2. Run evaluation: cd evaluation && python run_smartbugs_eval.py

Options:
    --resume    Resume from last checkpoint (skip already evaluated contracts)
    --category  Only evaluate one category: reentrancy, arithmetic, unchecked
"""

import os
import sys
import json
import re
import time
import argparse
import requests
from datetime import datetime
from pathlib import Path

# --- CONFIG ---
API_URL = os.getenv("API_URL", "http://localhost:8000/analyze")
DATASET_DIR = Path(__file__).parent / "external_datasets" / "SmartBugs-Curated" / "dataset"
MAPPING_FILE = Path(__file__).parent / "smartbugs_ground_truth.json"
OUTPUT_FILE = Path(__file__).parent / "smartbugs_evaluation_results.json"
CHECKPOINT_FILE = Path(__file__).parent / "smartbugs_checkpoint.json"

# Rate limit: delay between API calls (seconds)
DELAY_BETWEEN_CALLS = 3


# ============================================================
# PIPELINE EVALUATION
# ============================================================

def load_ground_truth(category_filter=None):
    """Load ground truth mapping, optionally filtered by category"""
    with open(MAPPING_FILE, "r") as f:
        data = json.load(f)

    contracts = data["contracts"]

    if category_filter:
        filter_map = {
            "reentrancy": "SWC-107",
            "arithmetic": "SWC-101",
            "unchecked": "SWC-104"
        }
        swc_filter = filter_map.get(category_filter)
        if swc_filter:
            contracts = {k: v for k, v in contracts.items() if v["swc_id"] == swc_filter}

    return contracts


def load_checkpoint():
    """Load checkpoint of already-evaluated contracts"""
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    return {"results": [], "evaluated_files": []}


def save_checkpoint(results, evaluated_files):
    """Save checkpoint after each contract"""
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({
            "results": results,
            "evaluated_files": evaluated_files,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)


def analyze_contract(filepath: Path) -> dict:
    """Send contract to API and return response"""
    with open(filepath, "rb") as f:
        files = {"file": (filepath.name, f, "text/plain")}
        response = requests.post(API_URL, files=files, timeout=300)

    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}: {response.text[:200]}"}

    return response.json()


def extract_verdict(api_response: dict) -> str:
    """Extract verdict from API response"""
    structured = api_response.get("ai_analysis_structured")
    if structured and isinstance(structured, dict):
        verdict = structured.get("verdict", "").upper()
        if verdict in ["VULNERABLE", "SAFE"]:
            return verdict

    llm = api_response.get("llm_analysis", {})
    verdict = llm.get("verdict", "").upper()
    if verdict in ["VULNERABLE", "SAFE"]:
        return verdict

    raw = api_response.get("ai_analysis", "")
    if "VULNERABLE" in raw.upper():
        return "VULNERABLE"
    if "SAFE" in raw.upper():
        return "SAFE"

    return "UNKNOWN"


def extract_detected_types(api_response: dict) -> list:
    """Extract detected vulnerability types from API response"""
    types = []
    structured = api_response.get("ai_analysis_structured")
    if structured and isinstance(structured, dict):
        for vuln in structured.get("vulnerabilities", []):
            vtype = vuln.get("type", "")
            swc = vuln.get("swc_id", "")
            types.append({"type": vtype, "swc_id": swc})
    return types


def calculate_metrics(results: list) -> dict:
    """Calculate detection metrics (all contracts are vulnerable)"""
    tp = 0
    fn = 0
    unknown = 0

    for r in results:
        predicted = r["predicted_verdict"]
        if predicted == "VULNERABLE":
            tp += 1
        elif predicted == "SAFE":
            fn += 1
        else:
            unknown += 1
            fn += 1

    total = len(results)
    recall = tp / total if total > 0 else 0
    type_matches = sum(1 for r in results if r.get("type_match"))
    type_accuracy = type_matches / total if total > 0 else 0

    return {
        "tp": tp, "fn": fn, "unknown": unknown, "total": total,
        "recall": round(recall, 4),
        "type_accuracy": round(type_accuracy, 4)
    }


# ============================================================
# SECONDARY FINDINGS VERIFICATION
# ============================================================

def read_contract(filepath: Path) -> str:
    """Read contract source code"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def get_solidity_version(code: str) -> float:
    """Extract Solidity version from pragma"""
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
    """Verify if a secondary finding is valid (True) or false alarm (False)"""
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


def normalize_swc(swc_id: str) -> str:
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    if match:
        return f"SWC-{match.group(1)}"
    return swc_id


def analyze_secondary(results: list):
    """Analyze secondary findings: verified real vs false alarms"""
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
        predicted_types = r.get("predicted_types", [])
        predicted_swcs = [normalize_swc(t.get("swc_id", "")) for t in predicted_types]

        # Recall per type
        if expected_swc in type_recall:
            type_recall[expected_swc]["total"] += 1
            if expected_swc in predicted_swcs:
                type_recall[expected_swc]["detected"] += 1
            else:
                primary_miss.append(r)

        # Secondary findings
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

def run_evaluation(resume=False, category_filter=None):
    """Main evaluation loop + per-type analysis"""
    print("=" * 70)
    print("DarkHotel Evaluation - SmartBugs-Curated Dataset")
    print("=" * 70)

    # Check API
    try:
        health = requests.get("http://localhost:8000/", timeout=5)
        info = health.json()
        print(f"API Status: {info.get('status')}")
        print(f"Model: {info.get('model')}")
    except requests.ConnectionError:
        print("ERROR: Backend not running! Start it first:")
        print("  cd backend && uvicorn main:app --port 8000")
        sys.exit(1)

    # Load ground truth
    ground_truth = load_ground_truth(category_filter)
    print(f"\nContracts to evaluate: {len(ground_truth)}")
    if category_filter:
        print(f"  Category filter: {category_filter}")

    type_counts = {}
    for v in ground_truth.values():
        t = v["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")
    print("-" * 70)

    # Resume?
    results = []
    evaluated_files = []
    if resume:
        checkpoint = load_checkpoint()
        results = checkpoint.get("results", [])
        evaluated_files = checkpoint.get("evaluated_files", [])
        if evaluated_files:
            print(f"\nResuming from checkpoint: {len(evaluated_files)} already evaluated")

    errors = []
    total = len(ground_truth)

    for i, (rel_path, truth) in enumerate(ground_truth.items(), 1):
        if rel_path in evaluated_files:
            continue

        filepath = DATASET_DIR / rel_path

        if not filepath.exists():
            print(f"[{i}/{total}] SKIP (not found): {rel_path}")
            errors.append({"file": rel_path, "error": "File not found"})
            continue

        print(f"\n[{i}/{total}] {filepath.name}")
        print(f"  Expected: VULNERABLE ({truth['type']})")

        try:
            start = time.time()
            response = analyze_contract(filepath)
            elapsed = time.time() - start

            if "error" in response:
                print(f"  ERROR: {response['error']}")
                errors.append({"file": rel_path, "error": response["error"]})
                continue

            verdict = extract_verdict(response)
            detected_types = extract_detected_types(response)

            correct = (verdict == "VULNERABLE")
            status = "OK" if correct else "MISSED"
            print(f"  Predicted: {verdict} | {status} | {elapsed:.1f}s")

            if detected_types:
                type_names = [f"{t['type']} ({t['swc_id']})" for t in detected_types[:3]]
                print(f"  Detected: {', '.join(type_names)}")

            type_match = False
            for dt in detected_types:
                if dt.get("swc_id") == truth["swc_id"]:
                    type_match = True
                    break

            result = {
                "file": rel_path,
                "filename": filepath.name,
                "expected_type": truth["type"],
                "expected_swc": truth["swc_id"],
                "predicted_verdict": verdict,
                "predicted_types": detected_types,
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

    # ============================================================
    # PART 1: Basic Metrics
    # ============================================================
    print("\n" + "=" * 70)
    print("PART 1 — DETECTION RESULTS")
    print("=" * 70)

    metrics = calculate_metrics(results)

    print(f"\nDetection (all contracts are vulnerable):")
    print(f"  Detected (TP):  {metrics['tp']}/{metrics['total']}")
    print(f"  Missed (FN):    {metrics['fn']}/{metrics['total']}")
    if metrics['unknown'] > 0:
        print(f"  Unknown:        {metrics['unknown']}")
    print(f"\n  Recall (Detection Rate): {metrics['recall']:.2%}")
    print(f"  Type Accuracy:           {metrics['type_accuracy']:.2%}")

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
    # PART 2: Per-Type & Secondary Analysis
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
            print(f"    {m['filename']} — expected {m['expected_swc']}, "
                  f"got {[t['swc_id'] for t in m['predicted_types']]}")

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
    # SUMMARY
    # ============================================================
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"  Primary Recall:       {total_detected}/{total_all} = {total_detected/total_all:.0%}" if total_all > 0 else "")
    if secondary_stats['total'] > 0:
        print(f"  Secondary Accuracy:   {secondary_stats['verified_true']}/{secondary_stats['total']} verified real "
              f"({secondary_stats['verified_true']/secondary_stats['total']:.0%})")
        print(f"  False Alarm Rate:     {secondary_stats['false_alarm']}/{secondary_stats['total']} "
              f"({secondary_stats['false_alarm']/secondary_stats['total']:.0%})")
    print(f"  Avg Analysis Time:    {sum(times)/len(times):.1f}s" if times else "")
    print(f"{'='*70}")

    # Save results
    output = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "dataset": "SmartBugs-Curated",
            "total_contracts": total,
            "evaluated": len(results),
            "errors": len(errors),
            "category_filter": category_filter,
            "api_url": API_URL
        },
        "metrics": metrics,
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

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: {OUTPUT_FILE}")

    if len(evaluated_files) >= total and CHECKPOINT_FILE.exists():
        os.remove(str(CHECKPOINT_FILE))
        print("Checkpoint cleaned up (evaluation complete)")

    print("=" * 70)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DarkHotel SmartBugs Evaluation")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--category", choices=["reentrancy", "arithmetic", "unchecked"],
                        help="Only evaluate one category")
    args = parser.parse_args()

    run_evaluation(resume=args.resume, category_filter=args.category)
