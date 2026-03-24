"""
DarkHotel Evaluation - Safe Contracts (False Positive Rate)
Runs the full 6-step pipeline on 23 verified SAFE contracts.
Any detection = False Positive.

Sources:
  - SWC Registry fixed versions (8 contracts)
  - Solidity by Example (10 contracts)
  - Solidity Documentation (5 contracts)

Usage:
    1. Start backend: cd backend && uvicorn main:app --port 8000
    2. Run evaluation: cd evaluation && python run_safe_contracts_eval.py

Options:
    --resume    Resume from last checkpoint
    --source    Only evaluate one source: swc_registry_fixed, solidity_by_example, solidity_docs
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
DATASET_DIR = Path(__file__).parent / "external_datasets" / "safe_contracts"
MAPPING_FILE = Path(__file__).parent / "safe_contracts_ground_truth.json"
OUTPUT_FILE = Path(__file__).parent / "safe_contracts_evaluation_results.json"
CHECKPOINT_FILE = Path(__file__).parent / "safe_contracts_checkpoint.json"

DELAY_BETWEEN_CALLS = 3


def load_ground_truth(source_filter=None):
    with open(MAPPING_FILE, "r") as f:
        data = json.load(f)

    contracts = data["contracts"]
    if source_filter:
        contracts = [c for c in contracts if c["source"] == source_filter]

    return contracts, data["metadata"]


def analyze_contract(filepath):
    """Send contract to DarkHotel API for analysis"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()

        if not code.strip():
            return {"error": "Empty file"}

        files = {"file": (os.path.basename(filepath), code, "text/plain")}
        response = requests.post(API_URL, files=files, timeout=300)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}: {response.text[:200]}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout (300s)"}
    except Exception as e:
        return {"error": str(e)}


def extract_verdict(result):
    """Extract verdict from API response"""
    if "error" in result:
        return "ERROR", []

    # ai_analysis is raw text string, ai_analysis_structured is dict
    structured = result.get("ai_analysis_structured", {})
    if structured and isinstance(structured, dict):
        verdict = structured.get("verdict", "").upper()
        vulns = structured.get("vulnerabilities", [])
        detected_types = []
        for v in vulns:
            vtype = v.get("type", v.get("vulnerability_type", ""))
            swc = v.get("swc_id", "")
            if vtype:
                detected_types.append({"type": vtype, "swc_id": swc})
        return verdict, detected_types

    # Fallback: parse raw text
    raw = result.get("ai_analysis", "") or ""
    if not isinstance(raw, str):
        raw = str(raw)
    if re.search(r'\bVULNERABLE\b', raw, re.IGNORECASE):
        return "VULNERABLE", [{"type": "Unknown (from raw text)", "swc_id": "N/A"}]
    elif re.search(r'\bSAFE\b', raw, re.IGNORECASE):
        return "SAFE", []

    return "UNKNOWN", []


def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return json.load(f)
    return {"completed": {}, "results": []}


def save_checkpoint(checkpoint):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(checkpoint, f, indent=2)


def run_evaluation(source_filter=None, resume=False):
    contracts, metadata = load_ground_truth(source_filter)
    total = len(contracts)

    print(f"\n{'='*70}")
    print(f"DarkHotel Safe Contracts Evaluation")
    print(f"{'='*70}")
    print(f"Total contracts: {total}")
    print(f"Expected verdict: ALL SAFE")
    print(f"API: {API_URL}")
    if source_filter:
        print(f"Filter: {source_filter}")
    print(f"{'='*70}\n")

    # Load checkpoint if resuming
    if resume:
        checkpoint = load_checkpoint()
        print(f"Resuming from checkpoint: {len(checkpoint['completed'])} already done")
    else:
        checkpoint = {"completed": {}, "results": []}

    start_time = time.time()

    for i, contract in enumerate(contracts):
        filepath = DATASET_DIR / contract["file"]
        filename = contract["file"]

        # Skip if already done
        if filename in checkpoint["completed"]:
            print(f"[{i+1}/{total}] SKIP (already done): {filename}")
            continue

        print(f"[{i+1}/{total}] Analyzing: {filename}...", end=" ", flush=True)

        t0 = time.time()
        result = analyze_contract(filepath)
        elapsed = time.time() - t0

        verdict, detected_types = extract_verdict(result)

        # For safe contracts: SAFE = correct, VULNERABLE = False Positive
        is_correct = verdict == "SAFE"
        is_fp = verdict == "VULNERABLE"

        status = "CORRECT" if is_correct else ("FP!" if is_fp else verdict)
        print(f"{verdict} ({elapsed:.1f}s) [{status}]")

        if detected_types:
            for dt in detected_types:
                print(f"   -> FP: {dt['type']} ({dt['swc_id']})")

        entry = {
            "file": filename,
            "source": contract["source"],
            "expected": "SAFE",
            "predicted_verdict": verdict,
            "is_correct": is_correct,
            "is_false_positive": is_fp,
            "detected_types": detected_types,
            "analysis_time": round(elapsed, 1),
            "description": contract["description"],
            "solidity_version": contract["solidity_version"],
        }

        checkpoint["results"].append(entry)
        checkpoint["completed"][filename] = True
        save_checkpoint(checkpoint)

        # Rate limit
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

    # Per-source breakdown
    sources = {}
    for r in results:
        src = r["source"]
        if src not in sources:
            sources[src] = {"total": 0, "correct": 0, "fp": 0, "error": 0}
        sources[src]["total"] += 1
        if r["is_correct"]:
            sources[src]["correct"] += 1
        if r["is_false_positive"]:
            sources[src]["fp"] += 1
        if r["predicted_verdict"] == "ERROR":
            sources[src]["error"] += 1

    # FP type breakdown
    fp_types = {}
    for r in results:
        if r["is_false_positive"]:
            for dt in r["detected_types"]:
                key = dt.get("type", "Unknown")
                if key not in fp_types:
                    fp_types[key] = []
                fp_types[key].append(r["file"])

    avg_time = sum(r["analysis_time"] for r in results) / max(n_total, 1)

    # === PRINT RESULTS ===
    print(f"\n{'='*70}")
    print(f"PART 1 — FALSE POSITIVE RESULTS")
    print(f"{'='*70}\n")
    print(f"All contracts are SAFE:")
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
    print(f"PART 2 — PER-SOURCE BREAKDOWN")
    print(f"{'='*70}")
    for src, stats in sources.items():
        pct = stats["correct"] / max(stats["total"], 1) * 100
        print(f"  {src:30s}: {stats['correct']}/{stats['total']} correct ({pct:.0f}%), {stats['fp']} FP")

    if fp_types:
        print(f"\n{'='*70}")
        print(f"PART 3 — FALSE POSITIVE DETAILS")
        print(f"{'='*70}")
        for fp_type, files in fp_types.items():
            print(f"\n    {fp_type} — {len(files)} false positives:")
            for f in files:
                print(f"      {f}")

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Specificity:          {n_correct}/{n_total} = {n_correct/max(n_total,1)*100:.0f}%")
    print(f"  False Positive Rate:  {n_fp}/{n_total} = {n_fp/max(n_total,1)*100:.0f}%")
    print(f"  Avg Analysis Time:    {avg_time:.1f}s")
    print(f"{'='*70}")

    # === SAVE RESULTS ===
    output = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "dataset": "Safe Contracts (FPR Evaluation)",
            "api_url": API_URL,
            "total_contracts": n_total,
            "source_filter": source_filter,
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
        "per_source": sources,
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
    parser = argparse.ArgumentParser(description="DarkHotel Safe Contracts Evaluation")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--source", type=str, default=None,
                        choices=["swc_registry_fixed", "solidity_by_example", "solidity_docs"],
                        help="Only evaluate one source")
    args = parser.parse_args()

    run_evaluation(source_filter=args.source, resume=args.resume)
