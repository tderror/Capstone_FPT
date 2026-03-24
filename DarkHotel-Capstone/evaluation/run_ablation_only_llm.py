"""
DarkHotel Ablation Study - Only LLM (No Slither, No RAG)
Sends raw Solidity code to Gemini with the same 3-type CoT prompt,
but with empty Slither warnings and no RAG context.

Tests whether LLM alone can detect reentrancy without pipeline support.

Usage:
    1. Set GEMINI_API_KEY in backend/.env
    2. Run: cd evaluation && python run_ablation_only_llm.py
"""

import os
import sys
import json
import re
import time
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
DATASET_DIR = Path(__file__).parent / "external_datasets" / "top_10_reentrancy"
OUTPUT_FILE = Path(__file__).parent / "ablation_only_llm_top10_results.json"
DELAY_BETWEEN_CALLS = 5  # Rate limit buffer

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
- Answer: [YES/NO] with evidence

### 2. INTEGER OVERFLOW/UNDERFLOW (SWC-101)
- Check: Are math operations (+, -, *, /) done WITHOUT SafeMath AND with exploitable impact?
- VULNERABLE: Solidity < 0.8.0 + no SafeMath + arithmetic affects balances, token amounts, or access control
- NOT VULNERABLE (do NOT report):
  - Solidity >= 0.8.0 (built-in overflow protection)
  - SafeMath library is used for the operation
  - Arithmetic only affects non-critical values (loop counters, timestamps, array indices, display values)
  - The overflow/underflow has no realistic exploit path (cannot be triggered by user input)
- Answer: [YES/NO] with evidence of EXPLOITABLE impact

### 3. UNCHECKED RETURN VALUE (SWC-104)
- Check: Are low-level calls (.send(), .call()) used WITHOUT checking the return value?
- VULNERABLE: addr.send(amount) or addr.call() without require() or if() check
- NOT VULNERABLE (do NOT report):
  - Return value is checked with require() or if()
  - .transfer() is used (auto-reverts on failure)
  - The call result is captured in a bool and checked
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


ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}


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


def extract_verdict(analysis_json: dict) -> str:
    if not analysis_json:
        return "UNKNOWN"
    verdict = analysis_json.get("verdict", "").upper()
    if verdict in ["VULNERABLE", "SAFE"]:
        return verdict
    return "UNKNOWN"


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
        swc = primary.get("swc_id", "")
        if swc:
            swcs.append(normalize_swc(swc))
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


def run_evaluation():
    print("=" * 70)
    print("ABLATION STUDY: Only LLM (No Slither, No RAG)")
    print("Dataset: Top 10 Reentrancy Contracts")
    print(f"Model: {MODEL_NAME}")
    print("=" * 70)

    client = genai.Client(api_key=API_KEY)

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
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()

            start = time.time()
            response = analyze_with_llm_only(code, client)
            elapsed = time.time() - start

            if not response["success"]:
                print(f"  ERROR: {response.get('error', 'Unknown')[:100]}")
                errors.append({"file": filename, "error": response.get("error", "")})
                continue

            analysis_json = response["analysis_json"]
            verdict = extract_verdict(analysis_json)
            detected_swcs = extract_detected_swcs(analysis_json)

            correct = (verdict == "VULNERABLE")
            type_match = "SWC-107" in detected_swcs
            status = "TP" if correct else "FN"

            swc_str = ", ".join(detected_swcs) if detected_swcs else "none"
            print(f"  Predicted: {verdict} | {status} | SWCs: {swc_str} | {elapsed:.1f}s")

            result = {
                "file": filename,
                "expected_type": truth["type"],
                "expected_swc": truth["swc_id"],
                "predicted_verdict": verdict,
                "predicted_swcs": detected_swcs,
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
    print("RESULTS - Ablation: Only LLM (Top 10 Reentrancy)")
    print("=" * 70)

    tp = sum(1 for r in results if r["correct"])
    fn = sum(1 for r in results if not r["correct"])
    type_matched = sum(1 for r in results if r["type_match"])
    total_evaluated = len(results)

    recall = tp / total_evaluated if total_evaluated > 0 else 0
    type_recall = type_matched / total_evaluated if total_evaluated > 0 else 0

    print(f"\n  Evaluated:  {total_evaluated}")
    print(f"  Errors:     {len(errors)}")
    print()
    print(f"  TP (VULNERABLE detected): {tp}")
    print(f"  FN (VULNERABLE missed):   {fn}")
    print()
    print(f"  Recall: {recall:.2%}")
    print(f"  SWC-107 Type Match: {type_recall:.2%} ({type_matched}/{total_evaluated})")

    # Detail
    print(f"\n{'='*70}")
    print("DETAIL PER CONTRACT")
    print(f"{'='*70}")
    print(f"  {'File':<45} {'Verdict':<13} {'SWC-107?':<10} {'Time'}")
    print("  " + "-" * 68)
    for r in results:
        tm = "YES" if r["type_match"] else "NO"
        print(f"  {r['file']:<43} {r['predicted_verdict']:<13} {tm:<10} {r['time_seconds']}s")

    # Comparison table
    print(f"\n{'='*70}")
    print("COMPARISON: Only LLM vs Full Pipeline")
    print(f"{'='*70}")
    print()
    print("| Configuration | TP | FN | Recall | SWC-107 Match |")
    print("|---------------|----|----|--------|---------------|")
    print(f"| Only LLM (no Slither, no RAG) | {tp} | {fn} | {recall:.2%} | {type_recall:.2%} |")
    print(f"| Full Pipeline (reference)     | 10 | 0  | 100.00% | 100.00% |")

    # Save results
    output = {
        "evaluation": "Ablation Study - Only LLM",
        "configuration": "Only LLM (no Slither, no RAG)",
        "model": MODEL_NAME,
        "timestamp": datetime.now().isoformat(),
        "dataset": "Top 10 Reentrancy Contracts",
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
