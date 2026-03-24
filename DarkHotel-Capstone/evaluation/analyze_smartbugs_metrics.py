"""
Analyze SmartBugs evaluation results with per-type metrics.

Calculates:
1. Recall per type: Does the system catch the primary (labeled) vulnerability?
2. False alarm rate: How often does LLM report clearly wrong secondary findings?

Secondary findings are verified automatically:
- Reentrancy: valid only if .call{value:}() exists (not just .send/.transfer)
- Integer Overflow: valid only if Solidity < 0.8.0 AND no SafeMath
- Unchecked Return Value: valid only if .send()/.call() without return check

Usage:
    cd evaluation
    python analyze_smartbugs_metrics.py
    python analyze_smartbugs_metrics.py --results smartbugs_evaluation_results_v2.json
"""

import json
import re
import argparse
from pathlib import Path

RESULTS_FILE = Path(__file__).parent / "smartbugs_evaluation_results.json"
DATASET_DIR = Path(__file__).parent / "external_datasets" / "SmartBugs-Curated" / "dataset"

# Map SmartBugs folder → SWC
FOLDER_SWC_MAP = {
    "reentrancy": "SWC-107",
    "arithmetic": "SWC-101",
    "unchecked_low_level_calls": "SWC-104"
}


def read_contract(filepath: Path) -> str:
    """Read contract source code"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def get_solidity_version(code: str) -> float:
    """Extract Solidity version from pragma. Returns 0.0 if not found."""
    match = re.search(r'pragma\s+solidity\s+[\^~>=]*(\d+\.\d+)', code)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return 0.0
    return 0.0


def has_safemath(code: str) -> bool:
    """Check if SafeMath is imported or used"""
    return bool(re.search(r'(SafeMath|using\s+SafeMath)', code))


def has_call_value(code: str) -> bool:
    """Check if .call{value:}() or .call.value() exists (real reentrancy risk)"""
    # Solidity >= 0.6: .call{value: X}("")
    # Solidity < 0.6: .call.value(X)()
    return bool(re.search(r'\.(call\s*\{|call\.value\s*\()', code))


def has_unchecked_send_or_call(code: str) -> bool:
    """Check if .send() or .call() is used without checking return value"""
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        # .send() without require/if
        if '.send(' in stripped:
            # Check if wrapped in require() or if()
            if not re.search(r'(require|if)\s*\(.*\.send\(', stripped):
                # Check if return value is captured
                if not re.search(r'(bool\s+\w+|success)\s*=', stripped):
                    return True
        # .call( without checking
        if '.call(' in stripped or '.call{' in stripped or '.call.value(' in stripped:
            if not re.search(r'(require|if)\s*\(.*\.(call|call\.value)', stripped):
                if not re.search(r'(bool\s+\w+|success)\s*[\,\)]\s*=', stripped):
                    # Check next few lines for require(success)
                    found_check = False
                    for j in range(i, min(i + 3, len(lines))):
                        if re.search(r'require\s*\(\s*(success|\w+)\s*\)', lines[j]):
                            found_check = True
                            break
                    if not found_check:
                        return True
    return False


def verify_secondary(swc_id: str, code: str) -> bool:
    """
    Verify if a secondary (non-labeled) vulnerability finding is valid.
    Returns True if the finding is justified, False if it's a false alarm.
    """
    if swc_id == "SWC-107":
        # Reentrancy: only valid if .call{value:}() exists
        return has_call_value(code)

    elif swc_id == "SWC-101":
        # Integer Overflow: only valid if Solidity < 0.8.0 AND no SafeMath
        version = get_solidity_version(code)
        if version >= 0.8:
            return False
        if has_safemath(code):
            return False
        # Check if there's actual arithmetic
        return bool(re.search(r'[\+\-\*]', code))

    elif swc_id == "SWC-104":
        # Unchecked Return Value: only valid if unchecked .send()/.call() exists
        return has_unchecked_send_or_call(code)

    return False


def normalize_swc(swc_id: str) -> str:
    """Normalize SWC ID variations"""
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    if match:
        return f"SWC-{match.group(1)}"
    return swc_id


def analyze(results_file: Path):
    """Main analysis"""
    print("=" * 70)
    print("SmartBugs Per-Type Metrics Analysis")
    print("=" * 70)

    with open(results_file, "r") as f:
        data = json.load(f)

    results = data["results"]
    print(f"Total contracts: {len(results)}")

    # === 1. Recall per type ===
    type_recall = {
        "SWC-107": {"label": "Reentrancy", "total": 0, "detected": 0},
        "SWC-101": {"label": "Integer Overflow/Underflow", "total": 0, "detected": 0},
        "SWC-104": {"label": "Unchecked Return Value", "total": 0, "detected": 0}
    }

    # === 2. Secondary findings analysis ===
    secondary_stats = {
        "total": 0,          # Total secondary findings
        "verified_true": 0,  # Verified as real vulnerability
        "false_alarm": 0,    # Clearly wrong
        "details": []        # Per-contract details
    }

    # === 3. Primary detection (miss = wrong primary) ===
    primary_miss = []

    for r in results:
        expected_swc = normalize_swc(r["expected_swc"])
        predicted_types = r.get("predicted_types", [])
        predicted_swcs = [normalize_swc(t.get("swc_id", "")) for t in predicted_types]

        # Recall: did system detect the labeled vulnerability?
        if expected_swc in type_recall:
            type_recall[expected_swc]["total"] += 1
            if expected_swc in predicted_swcs:
                type_recall[expected_swc]["detected"] += 1
            else:
                primary_miss.append(r)

        # Secondary findings: any SWC reported that isn't the label
        secondary_swcs = [s for s in predicted_swcs if s and s != expected_swc]
        # Deduplicate
        secondary_swcs = list(set(secondary_swcs))

        if secondary_swcs:
            # Get contract folder from file path
            rel_path = r["file"]
            folder = rel_path.split("/")[0]
            sol_file = DATASET_DIR / rel_path

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
                        "reason": _get_reason(sec_swc, code)
                    })

    # === Print Results ===

    print(f"\n{'='*70}")
    print("1. RECALL PER TYPE (Primary vulnerability detection)")
    print(f"{'='*70}")
    for swc, stats in type_recall.items():
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {stats['label']:35s} ({swc}): {stats['detected']}/{stats['total']} = {rate:.0%}")

    total_detected = sum(s["detected"] for s in type_recall.values())
    total_all = sum(s["total"] for s in type_recall.values())
    print(f"  {'Overall':35s}       : {total_detected}/{total_all} = {total_detected/total_all:.0%}")

    if primary_miss:
        print(f"\n  MISSED contracts:")
        for m in primary_miss:
            print(f"    {m['filename']} — expected {m['expected_swc']}, got {[t['swc_id'] for t in m['predicted_types']]}")

    print(f"\n{'='*70}")
    print("2. SECONDARY FINDINGS ANALYSIS")
    print(f"{'='*70}")
    print(f"  Total secondary findings: {secondary_stats['total']}")
    print(f"  Verified real:            {secondary_stats['verified_true']}")
    print(f"  False alarms:             {secondary_stats['false_alarm']}")

    if secondary_stats['total'] > 0:
        false_rate = secondary_stats['false_alarm'] / secondary_stats['total']
        true_rate = secondary_stats['verified_true'] / secondary_stats['total']
        print(f"\n  Verified real rate:  {true_rate:.1%}")
        print(f"  False alarm rate:   {false_rate:.1%}")

    if secondary_stats["details"]:
        print(f"\n  False alarm details:")
        # Group by false_alarm_swc
        by_swc = {}
        for d in secondary_stats["details"]:
            swc = d["false_alarm_swc"]
            if swc not in by_swc:
                by_swc[swc] = []
            by_swc[swc].append(d)

        for swc, items in sorted(by_swc.items()):
            swc_label = {
                "SWC-107": "Reentrancy",
                "SWC-101": "Integer Overflow",
                "SWC-104": "Unchecked Return Value"
            }.get(swc, swc)
            print(f"\n    {swc_label} ({swc}) — {len(items)} false alarms:")
            for item in items[:5]:
                print(f"      {item['file']}: {item['reason']}")
            if len(items) > 5:
                print(f"      ... and {len(items) - 5} more")

    # === Summary ===
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"  Primary Recall:       {total_detected}/{total_all} = {total_detected/total_all:.0%}")
    if secondary_stats['total'] > 0:
        print(f"  Secondary Accuracy:   {secondary_stats['verified_true']}/{secondary_stats['total']} verified real "
              f"({secondary_stats['verified_true']/secondary_stats['total']:.0%})")
        print(f"  False Alarm Rate:     {secondary_stats['false_alarm']}/{secondary_stats['total']} "
              f"({secondary_stats['false_alarm']/secondary_stats['total']:.0%})")
    else:
        print(f"  No secondary findings to analyze")
    print(f"{'='*70}")

    # Save detailed results
    output = {
        "recall_per_type": {swc: {
            "label": s["label"],
            "detected": s["detected"],
            "total": s["total"],
            "recall": round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0
        } for swc, s in type_recall.items()},
        "secondary_analysis": {
            "total": secondary_stats["total"],
            "verified_true": secondary_stats["verified_true"],
            "false_alarm": secondary_stats["false_alarm"],
            "false_alarm_details": secondary_stats["details"]
        },
        "primary_misses": [{"file": m["filename"], "expected": m["expected_swc"]} for m in primary_miss]
    }

    output_file = results_file.parent / results_file.name.replace(".json", "_metrics.json")
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nDetailed metrics saved to: {output_file}")


def _get_reason(swc_id: str, code: str) -> str:
    """Get human-readable reason why a secondary finding is a false alarm"""
    if swc_id == "SWC-107":
        if not has_call_value(code):
            return "No .call{value:}() found — only .send()/.transfer() (2300 gas, cannot reenter)"
        return "Unknown reason"
    elif swc_id == "SWC-101":
        version = get_solidity_version(code)
        if version >= 0.8:
            return f"Solidity {version} has built-in overflow protection"
        if has_safemath(code):
            return "SafeMath is used"
        return "No arithmetic operations found"
    elif swc_id == "SWC-104":
        return "All .send()/.call() return values are checked"
    return "Unknown"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze SmartBugs evaluation metrics")
    parser.add_argument("--results", type=str, default=None,
                        help="Path to evaluation results JSON")
    args = parser.parse_args()

    results_path = Path(args.results) if args.results else RESULTS_FILE
    analyze(results_path)
