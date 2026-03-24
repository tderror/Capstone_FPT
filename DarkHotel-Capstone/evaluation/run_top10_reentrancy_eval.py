"""
DarkHotel Evaluation - Top 10 Reentrancy Contracts
Runs the full 6-step pipeline on 10 real-world reentrancy contracts.

All 10 contracts are expected to be VULNERABLE with Reentrancy (SWC-107).

Usage:
    1. Start backend: cd backend && uvicorn main:app --port 8000
    2. Run evaluation: cd evaluation && python run_top10_reentrancy_eval.py
"""

import os
import sys
import json
import re
import time
import requests
from datetime import datetime
from pathlib import Path

# --- CONFIG ---
API_URL = os.getenv("API_URL", "http://localhost:8000/analyze")
DATASET_DIR = Path(__file__).parent / "external_datasets" / "top_10_reentrancy"
OUTPUT_FILE = Path(__file__).parent / "top10_reentrancy_results.json"

DELAY_BETWEEN_CALLS = 3

# Ground truth: all 10 contracts are Reentrancy (SWC-107)
GROUND_TRUTH = {
    "01_CB_BANK.sol":                       {"type": "Reentrancy", "swc_id": "SWC-107"},
    "02_CA_BANK.sol":                       {"type": "Reentrancy", "swc_id": "SWC-107"},
    "03_p_bank.sol":                        {"type": "Reentrancy", "swc_id": "SWC-107"},
    "04_BoomerangLiquidity_POWH.sol":       {"type": "Reentrancy", "swc_id": "SWC-107"},
    "05_BoomerangLiquidity_FLM.sol":        {"type": "Reentrancy", "swc_id": "SWC-107"},
    "06_IronHands.sol":                     {"type": "Reentrancy", "swc_id": "SWC-107"},
    "07_X3ProfitMainFundTransfer.sol":      {"type": "Reentrancy", "swc_id": "SWC-107"},
    "08_SOLIDBLOCK.sol":                    {"type": "Reentrancy", "swc_id": "SWC-107"},
    "09_TwelveHourAuction.sol":             {"type": "Reentrancy", "swc_id": "SWC-107"},
    "10_cb_BANK.sol":                       {"type": "Reentrancy", "swc_id": "SWC-107"},
}


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
        # Primary vulnerability
        primary = structured.get("primary_vulnerability")
        if primary and isinstance(primary, dict):
            types.append({
                "type": primary.get("type", ""),
                "swc_id": primary.get("swc_id", ""),
                "severity": primary.get("severity", ""),
                "location": primary.get("location", "")
            })
        # Secondary warnings
        for warn in structured.get("secondary_warnings", []):
            if isinstance(warn, dict):
                types.append({
                    "type": warn.get("type", ""),
                    "swc_id": warn.get("swc_id", ""),
                    "severity": warn.get("severity", ""),
                    "location": warn.get("location", "")
                })
        # Vulnerabilities list (fallback)
        if not types:
            for vuln in structured.get("vulnerabilities", []):
                types.append({
                    "type": vuln.get("type", ""),
                    "swc_id": vuln.get("swc_id", ""),
                    "severity": vuln.get("severity", ""),
                    "location": vuln.get("location", "")
                })
    return types


def normalize_swc(swc_id: str) -> str:
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    if match:
        return f"SWC-{match.group(1)}"
    return swc_id


def run_evaluation():
    print("=" * 70)
    print("DarkHotel Evaluation - Top 10 Reentrancy Contracts")
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

    print(f"\nDataset: {DATASET_DIR}")
    print(f"Contracts: {len(GROUND_TRUTH)}")
    print(f"Expected: ALL VULNERABLE (Reentrancy SWC-107)")
    print("-" * 70)

    results = []
    errors = []
    total = len(GROUND_TRUTH)

    for i, (filename, truth) in enumerate(GROUND_TRUTH.items(), 1):
        filepath = DATASET_DIR / filename

        if not filepath.exists():
            print(f"\n[{i}/{total}] SKIP (not found): {filename}")
            errors.append({"file": filename, "error": "File not found"})
            continue

        print(f"\n[{i}/{total}] {filename}")
        print(f"  Expected: VULNERABLE ({truth['type']} - {truth['swc_id']})")

        try:
            start = time.time()
            response = analyze_contract(filepath)
            elapsed = time.time() - start

            if "error" in response:
                print(f"  ERROR: {response['error']}")
                errors.append({"file": filename, "error": response["error"]})
                continue

            verdict = extract_verdict(response)
            detected_types = extract_detected_types(response)

            # Check if predicted VULNERABLE
            correct = (verdict == "VULNERABLE")

            # Check if SWC-107 specifically detected
            predicted_swcs = [normalize_swc(t.get("swc_id", "")) for t in detected_types]
            type_match = "SWC-107" in predicted_swcs

            status = "TP" if correct else "FN"
            type_status = "SWC-107 MATCHED" if type_match else "SWC-107 NOT MATCHED"
            print(f"  Predicted: {verdict} | {status} | {type_status} | {elapsed:.1f}s")

            if detected_types:
                for t in detected_types[:5]:
                    print(f"    - {t['type']} ({t['swc_id']}) [{t.get('severity', '')}] {t.get('location', '')}")

            result = {
                "file": filename,
                "expected_type": truth["type"],
                "expected_swc": truth["swc_id"],
                "predicted_verdict": verdict,
                "predicted_types": detected_types,
                "type_match": type_match,
                "correct": correct,
                "time_seconds": round(elapsed, 1)
            }
            results.append(result)

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            errors.append({"file": filename, "error": str(e)})

        if i < total:
            time.sleep(DELAY_BETWEEN_CALLS)

    # ============================================================
    # METRICS
    # ============================================================
    print("\n" + "=" * 70)
    print("RESULTS - Top 10 Reentrancy Evaluation")
    print("=" * 70)

    tp = sum(1 for r in results if r["predicted_verdict"] == "VULNERABLE")
    fn = sum(1 for r in results if r["predicted_verdict"] != "VULNERABLE")
    type_matched = sum(1 for r in results if r["type_match"])

    total_evaluated = len(results)
    recall = tp / total_evaluated if total_evaluated > 0 else 0
    type_recall = type_matched / total_evaluated if total_evaluated > 0 else 0

    print(f"\n  Evaluated:  {total_evaluated}")
    print(f"  Errors:     {len(errors)}")
    print()
    print(f"  TP (VULNERABLE detected): {tp}")
    print(f"  FN (VULNERABLE missed):   {fn}")
    print(f"  TN:                        0  (no safe contracts in dataset)")
    print(f"  FP:                        0  (no safe contracts in dataset)")
    print()
    print(f"  Recall: {recall:.2%}")
    print(f"  SWC-107 Type Match: {type_recall:.2%} ({type_matched}/{total_evaluated})")

    # Per-contract detail
    print(f"\n{'='*70}")
    print("DETAIL PER CONTRACT")
    print(f"{'='*70}")
    print(f"{'File':<45} {'Verdict':<13} {'SWC-107?':<10} {'Time':<6}")
    print("-" * 70)
    for r in results:
        v = r["predicted_verdict"]
        tm = "YES" if r["type_match"] else "NO"
        t = f"{r['time_seconds']}s"
        print(f"  {r['file']:<43} {v:<13} {tm:<10} {t:<6}")

    # Missed contracts
    missed = [r for r in results if not r["correct"]]
    if missed:
        print(f"\n{'='*70}")
        print("MISSED CONTRACTS (False Negatives)")
        print(f"{'='*70}")
        for r in missed:
            print(f"  {r['file']}: predicted {r['predicted_verdict']}")
            if r["predicted_types"]:
                for t in r["predicted_types"]:
                    print(f"    - {t['type']} ({t['swc_id']})")

    # Table format
    print(f"\n{'='*70}")
    print("TABLE FORMAT (for docs)")
    print(f"{'='*70}")
    print()
    print("| Dataset | TP | TN | FP | FN | Recall |")
    print("|---------|----|----|----|----|--------|")
    print(f"| Top-10 Reentrancy (vulnerable) | {tp} | 0 | 0 | {fn} | {recall:.2%} |")

    # Save results
    output = {
        "evaluation": "Top 10 Reentrancy Contracts",
        "timestamp": datetime.now().isoformat(),
        "dataset": "external_datasets/top_10_reentrancy",
        "total_contracts": total,
        "metrics": {
            "tp": tp,
            "tn": 0,
            "fp": 0,
            "fn": fn,
            "recall": round(recall, 4),
            "type_match_rate": round(type_recall, 4)
        },
        "results": results,
        "errors": errors
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    run_evaluation()
