"""
DarkHotel Evaluation - GPTScan Top200 (False Positive Rate on Production Contracts)
Runs the full 6-step pipeline on 225 single-file SAFE production contracts.
Any detection = False Positive.

Dataset: GPTScan Top200 (303 projects, 241 single-file, 16 empty -> 225 valid)
  - Top 200 market cap DeFi contracts from 6 chains (ETH, BSC, Polygon, Arbitrum, Fantom, Avalanche)
  - All production-deployed, audited contracts -> ground truth = SAFE
  - Source: https://github.com/MetaTrustLabs/GPTScan-Top200

Usage:
    1. Start backend: cd backend && uvicorn main:app --port 8000
    2. Run evaluation: cd evaluation && python run_top200_eval.py
    3. Resume if interrupted: python run_top200_eval.py --resume
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
DATASET_DIR = Path(__file__).parent / "external_datasets" / "GPTScan-Top200"
OUTPUT_FILE = Path(__file__).parent / "top200_evaluation_results.json"
CHECKPOINT_FILE = Path(__file__).parent / "top200_checkpoint.json"

DELAY_BETWEEN_CALLS = 3
REQUEST_TIMEOUT = 600  # 10 minutes for large files
MIN_FILE_LINES = 10    # Skip files smaller than this


def discover_contracts():
    """Scan dataset directory for single-file .sol contracts, skip empty/multi-file"""
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

            # Extract pragma
            pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
            pragma = pragma_match.group(1).strip() if pragma_match else "unknown"

            # Extract chain from dir name
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


def analyze_contract(filepath):
    """Send contract to DarkHotel API for analysis"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        if not code.strip():
            return {"error": "Empty file"}

        files = {"file": (os.path.basename(filepath), code, "text/plain")}
        response = requests.post(API_URL, files=files, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}: {response.text[:200]}"}
    except requests.exceptions.Timeout:
        return {"error": f"Timeout ({REQUEST_TIMEOUT}s)"}
    except Exception as e:
        return {"error": str(e)}


def extract_verdict(result):
    """Extract verdict from API response"""
    if "error" in result:
        return "ERROR", []

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


def run_evaluation(resume=False):
    contracts = discover_contracts()
    total = len(contracts)

    if total == 0:
        print("No contracts found! Check DATASET_DIR path.")
        return

    print(f"\n{'='*70}")
    print(f"DarkHotel GPTScan Top200 Evaluation (FPR)")
    print(f"{'='*70}")
    print(f"Total contracts: {total}")
    print(f"Expected verdict: ALL SAFE")
    print(f"API: {API_URL}")
    print(f"Timeout: {REQUEST_TIMEOUT}s per contract")
    print(f"{'='*70}\n")

    # Load checkpoint if resuming
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

        # Skip if already done
        if project in checkpoint["completed"]:
            continue

        print(f"[{i+1}/{total}] {contract['filename']} ({contract['lines']} lines, {contract['chain']})...", end=" ", flush=True)

        t0 = time.time()
        result = analyze_contract(filepath)
        elapsed = time.time() - t0

        verdict, detected_types = extract_verdict(result)

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

        checkpoint["results"].append(entry)
        checkpoint["completed"][project] = True
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

    # Per-chain breakdown
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

    # Per-pragma breakdown (group by major version)
    pragma_groups = {}
    for r in results:
        pragma = r["pragma"]
        # Group: extract major.minor
        ver_match = re.search(r'0\.(\d+)', pragma)
        if ver_match:
            minor = int(ver_match.group(1))
            group = f"0.{minor}.x"
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
    print(f"PART 1 — FALSE POSITIVE RESULTS")
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
            for f in files[:20]:  # Show max 20
                print(f"      {f}")
            if len(files) > 20:
                print(f"      ... and {len(files)-20} more")

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
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
            "timestamp": datetime.now().isoformat(),
            "dataset": "GPTScan Top200 (Production DeFi Contracts)",
            "dataset_source": "https://github.com/MetaTrustLabs/GPTScan-Top200",
            "api_url": API_URL,
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
    parser = argparse.ArgumentParser(description="DarkHotel GPTScan Top200 Evaluation (FPR)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    args = parser.parse_args()

    run_evaluation(resume=args.resume)
