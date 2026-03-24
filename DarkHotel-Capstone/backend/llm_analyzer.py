"""
Advanced LLM Analyzer với Chain-of-Thought Prompting
Using Google GenAI SDK
"""
from google import genai
import json
import re
import time
from typing import Dict, List
import os

class LLMAnalyzer:
    """
    Wrapper cho LLM analysis với advanced prompting techniques
    Using new Google GenAI SDK
    """

    def __init__(self, api_key: str,
                 model: str = "gemini-2.5-pro"):
        self.api_key = api_key
        self.model = model

        # Initialize GenAI client (API key passed directly)
        self.client = genai.Client(api_key=api_key)

        self.max_retries = 5
        self.retry_delay = 60

    def create_advanced_prompt(
        self,
        code: str,
        slither_warnings: List[str],
        rag_context: List[Dict]
    ) -> str:
        """
        Tạo prompt với Chain-of-Thought reasoning

        Args:
            code: Original Solidity code
            slither_warnings: Warnings from Slither
            rag_context: Similar cases from RAG

        Returns:
            Formatted prompt string
        """

        # Format RAG context (v6 — knowledge-enriched: root_cause, trigger, fix)
        rag_section = ""
        if rag_context and rag_context[0].get('vulnerability_type') != 'No data':
            rag_section = "## HISTORICAL CASES (Similar vulnerabilities from real audits):\n"
            for i, case in enumerate(rag_context[:3], 1):
                code_snippet = case.get('code_snippet_vulnerable', '')
                swc_id = case.get('swc_id', '')
                severity = case.get('severity', '')
                audit = case.get('audit_company', '')
                root_cause = case.get('root_cause', '')
                trigger = case.get('trigger_condition', '')
                fix = case.get('fix_solution', '')

                rag_section += f"""
### Case {i}: {case.get('vulnerability_type', 'Unknown')} {f'({swc_id})' if swc_id else ''} - Similarity: {case.get('similarity', 0):.2f}
**Severity**: {severity}
**Function**: {case.get('function', 'N/A')} @ {case.get('line_number', 'N/A')}
**Audit**: {audit}
"""
                if root_cause:
                    rag_section += f"**Root Cause**: {root_cause}\n"
                if trigger:
                    rag_section += f"**Trigger Condition**: {trigger}\n"
                if fix:
                    rag_section += f"**Fix Solution**: {fix}\n"
                rag_section += f"""**Vulnerable Code**:
```solidity
{code_snippet}
```
"""
        else:
            rag_section = "## HISTORICAL CASES:\nNo similar cases found in database.\n"

        # Format Slither warnings (NEW: Handle smart wrapper warnings)
        slither_section = "## STATIC ANALYSIS (Slither):\n"
        if slither_warnings and len(slither_warnings) > 0:
            first_warning = slither_warnings[0]

            # Check if Slither FAILED (warning from smart wrapper)
            if first_warning.startswith('⚠️ SLITHER UNAVAILABLE'):
                slither_section += f"{first_warning}\n\n"
                slither_section += "**IMPORTANT:** You MUST perform thorough manual code review.\n"
                slither_section += "Rely heavily on RAG similar cases and your own analysis.\n"

            # Check if it's clean format: "[High] Reentrancy at lines..."
            elif first_warning.startswith('['):
                slither_section += "**CRITICAL WARNINGS FOUND:**\n"
                for warning in slither_warnings:
                    slither_section += f"  {warning}\n"
                slither_section += "\n⚠️ PAY SPECIAL ATTENTION to these line numbers!\n"

            # Check if Slither ran successfully but found nothing
            elif first_warning == "No vulnerabilities detected by Slither":
                slither_section += "- Slither found no vulnerabilities\n"
                slither_section += "- BUT: Slither has high false negative rate!\n"
                slither_section += "- STILL check code carefully, especially patterns from RAG.\n"

            else:
                # Generic format fallback
                for warning in slither_warnings:
                    slither_section += f"- {warning}\n"
        else:
            slither_section += "- No Slither analysis available\n"

        # IMPROVED PROMPT: Systematic checking with strict evidence + primary/secondary output
        prompt = f"""You are an expert blockchain security auditor. Your task is to SYSTEMATICALLY check the Solidity code for the following 3 vulnerability types.

{slither_section}

{rag_section}

## IMPORTANT — EVIDENCE CONTEXT:
The historical cases above are examples of KNOWN vulnerabilities from audit reports.
Their presence does NOT imply the current contract is vulnerable.
Many secure contracts use identical patterns (withdraw, .call, transfer) with proper
protections (nonReentrant, Checks-Effects-Interactions, require guards).
Evaluate the CURRENT code on its own merits. Only flag vulnerabilities you can
demonstrate with a concrete exploit scenario in the current code.

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
13. CRITICAL — Solidity >= 0.8.0 makes SWC-101 IMPOSSIBLE. Do NOT report Integer Overflow for ^0.8.x contracts under ANY circumstances, even if RAG similar cases suggest it
14. ERC20 token operations (IERC20.transfer, IERC20.transferFrom, IERC20.approve) are SAFE high-level calls. Do NOT confuse them with low-level address.call() or address.send()

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

    def _filter_pragma_080(self, analysis_json: dict, solidity_version: str) -> dict:
        """
        Post-processing: Remove SWC-101 if Solidity >= 0.8.0
        Solidity 0.8.x has built-in overflow/underflow protection.
        """
        if not analysis_json or not solidity_version:
            return analysis_json

        # Parse version from pragma (e.g., "^0.8.26", ">=0.8.0", "0.8.4")
        ver_match = re.search(r'0\.(\d+)\.(\d+)', solidity_version)
        if not ver_match:
            return analysis_json

        minor = int(ver_match.group(1))
        if minor < 8:
            return analysis_json  # < 0.8.0, SWC-101 is valid

        # Solidity >= 0.8.0 → remove all SWC-101
        removed = False

        # Filter primary_vulnerability
        primary = analysis_json.get("primary_vulnerability")
        if primary and primary.get("swc_id") == "SWC-101":
            print(f"[PRAGMA-FILTER] Removed SWC-101 primary (Solidity {solidity_version} has built-in overflow protection)")
            analysis_json["primary_vulnerability"] = None
            removed = True

        # Filter vulnerabilities list
        vulns = analysis_json.get("vulnerabilities", [])
        filtered = [v for v in vulns if v.get("swc_id") != "SWC-101"]
        if len(filtered) < len(vulns):
            print(f"[PRAGMA-FILTER] Removed {len(vulns) - len(filtered)} SWC-101 from vulnerabilities (Solidity >= 0.8.0)")
            analysis_json["vulnerabilities"] = filtered
            removed = True

        # Filter secondary_warnings
        secondary = analysis_json.get("secondary_warnings", [])
        filtered_sec = [s for s in secondary if s.get("swc_id") != "SWC-101"]
        if len(filtered_sec) < len(secondary):
            analysis_json["secondary_warnings"] = filtered_sec
            removed = True

        # If primary was removed, promote from remaining vulns or secondary_warnings
        if analysis_json.get("primary_vulnerability") is None:
            if analysis_json.get("vulnerabilities"):
                analysis_json["primary_vulnerability"] = analysis_json["vulnerabilities"][0]
            elif analysis_json.get("secondary_warnings"):
                analysis_json["primary_vulnerability"] = analysis_json["secondary_warnings"][0]

        # If no findings remain at all, change verdict to SAFE
        if removed and not analysis_json.get("primary_vulnerability") \
           and not analysis_json.get("vulnerabilities") \
           and not analysis_json.get("secondary_warnings"):
            if analysis_json.get("verdict") == "VULNERABLE":
                print(f"[PRAGMA-FILTER] All findings were SWC-101 -> verdict changed to SAFE")
                analysis_json["verdict"] = "SAFE"

        return analysis_json

    def _parse_json_response(self, text: str) -> dict:
        """Parse JSON from LLM response with multiple fallback strategies"""
        if not text:
            return None

        # Strategy 1: Direct parse (ideal - LLM returned pure JSON)
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: Extract from markdown code blocks ```json ... ```
        match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # Strategy 3: Find outermost JSON object in text
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except (json.JSONDecodeError, ValueError):
                pass

        print("[LLM] WARNING: Could not parse JSON from response")
        return None

    # Target SWC types - anything outside this is filtered out
    ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}

    def _filter_out_of_scope(self, analysis_json: dict) -> dict:
        """Filter out vulnerabilities that are not in the 3 target SWC types."""
        if not analysis_json:
            return analysis_json

        # Filter primary_vulnerability
        primary = analysis_json.get("primary_vulnerability")
        if primary and primary.get("swc_id") not in self.ALLOWED_SWCS:
            print(f"[POST-FILTER] Removed out-of-scope primary: {primary.get('swc_id')} ({primary.get('type')})")
            analysis_json["primary_vulnerability"] = None

        # Filter secondary_warnings
        secondaries = analysis_json.get("secondary_warnings", [])
        filtered_sec = [s for s in secondaries if s.get("swc_id") in self.ALLOWED_SWCS]
        removed = len(secondaries) - len(filtered_sec)
        if removed > 0:
            print(f"[POST-FILTER] Removed {removed} out-of-scope secondary warnings")
        analysis_json["secondary_warnings"] = filtered_sec

        # Filter vulnerabilities list
        vulns = analysis_json.get("vulnerabilities", [])
        filtered_vulns = [v for v in vulns if v.get("swc_id") in self.ALLOWED_SWCS]
        analysis_json["vulnerabilities"] = filtered_vulns

        # If primary was removed, promote from remaining vulns or secondary_warnings
        if analysis_json.get("primary_vulnerability") is None:
            if filtered_vulns:
                analysis_json["primary_vulnerability"] = filtered_vulns[0]
            elif filtered_sec:
                analysis_json["primary_vulnerability"] = filtered_sec[0]

        # If no findings remain at all, set verdict to SAFE
        if not analysis_json.get("primary_vulnerability") \
           and not filtered_vulns \
           and not filtered_sec:
            if analysis_json.get("verdict") == "VULNERABLE":
                print("[POST-FILTER] All findings were out-of-scope -> verdict changed to SAFE")
                analysis_json["verdict"] = "SAFE"

        return analysis_json

    def analyze(
        self,
        code: str,
        slither_warnings: List[str],
        rag_context: List[Dict],
        use_advanced_prompt: bool = True,
        solidity_version: str = None
    ) -> Dict:
        """
        Gửi code lên LLM để phân tích

        Returns:
            {
                'success': True/False,
                'analysis': 'LLM response text',
                'model': 'gemini-2.5-pro',
                'prompt_tokens': 1234,
                'error': None
            }
        """

        if use_advanced_prompt:
            prompt = self.create_advanced_prompt(code, slither_warnings, rag_context)
        else:
            # Simple prompt (fallback)
            prompt = f"""Analyze this Solidity code for vulnerabilities:

{code}

Slither warnings: {slither_warnings}
"""

        # Log prompt before sending to AI
        print("\n=== BEFORE SENDING TO AI ===")
        print(f"Model: {self.model}")
        print(f"Slither warnings count: {len(slither_warnings)}")
        print(f"RAG context count: {len(rag_context)}")
        print(f"Prompt length: {len(prompt)} characters")
        print("=" * 40)

        # System message prefix
        system_prefix = "You are an expert blockchain security auditor. Output ONLY valid JSON.\n\n"
        full_prompt = system_prefix + prompt

        # Retry logic with exponential backoff
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    wait_time = self.retry_delay * (2 ** (attempt - 1))
                    print(f"\n[RETRY] Attempt {attempt + 1}/{self.max_retries} after {wait_time}s...")
                    time.sleep(wait_time)

                # Use new Google GenAI SDK
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=full_prompt
                )

                # Extract text from response
                analysis = response.text

                # Parse JSON from LLM response
                analysis_json = self._parse_json_response(analysis)

                # Post-processing: filter out-of-scope SWC types
                if analysis_json:
                    analysis_json = self._filter_out_of_scope(analysis_json)

                # Post-processing: filter SWC-101 for Solidity >= 0.8.0
                if analysis_json and solidity_version:
                    analysis_json = self._filter_pragma_080(analysis_json, solidity_version)

                print("\n=== AI RESPONSE ===")
                print(f"Response length: {len(analysis)} characters")
                print(f"JSON parsed: {'Yes' if analysis_json else 'No (raw text fallback)'}")
                if analysis_json:
                    print(f"Verdict: {analysis_json.get('verdict', 'N/A')}")
                    print(f"Vulnerabilities: {len(analysis_json.get('vulnerabilities', []))}")
                print("=" * 40)

                # Extract token counts from usage metadata if available
                prompt_tokens = 0
                completion_tokens = 0
                if hasattr(response, 'usage_metadata') and response.usage_metadata:
                    prompt_tokens = getattr(response.usage_metadata, 'prompt_token_count', 0) or 0
                    completion_tokens = getattr(response.usage_metadata, 'candidates_token_count', 0) or 0

                return {
                    'success': True,
                    'analysis': analysis,
                    'analysis_json': analysis_json,
                    'model': self.model,
                    'prompt_tokens': prompt_tokens,
                    'completion_tokens': completion_tokens,
                    'error': None
                }

            except Exception as e:
                error_msg = str(e)
                print(f"Error on attempt {attempt + 1}: {error_msg}")

                # Check for rate limiting
                if "429" in error_msg or "quota" in error_msg.lower() or "rate" in error_msg.lower():
                    if attempt < self.max_retries - 1:
                        # Parse retryDelay from API response if available
                        retry_match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                        if retry_match:
                            api_delay = float(retry_match.group(1)) + 5  # add 5s buffer
                        else:
                            api_delay = self.retry_delay * (2 ** attempt)
                        print(f"   -> Rate limited, waiting {api_delay:.0f}s before retry...")
                        time.sleep(api_delay)
                        continue
                    else:
                        return {
                            'success': False,
                            'analysis': None,
                            'analysis_json': None,
                            'error': f"Rate limit error after {self.max_retries} retries"
                        }

                # Other errors
                if attempt < self.max_retries - 1:
                    print(f"   -> Retrying...")
                    continue

                return {
                    'success': False,
                    'analysis': None,
                    'analysis_json': None,
                    'error': f"Error after {self.max_retries} attempts: {error_msg}"
                }

        # If loop completes without returning (shouldn't happen)
        return {
            'success': False,
            'analysis': None,
            'analysis_json': None,
            'error': "Maximum retries exceeded"
        }


# Test
if __name__ == "__main__":
    # Cần API key để test
    API_KEY = os.getenv("GEMINI_API_KEY", "")

    llm = LLMAnalyzer(API_KEY)

    test_code = """
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
    """

    slither_warnings = ["Reentrancy (HIGH impact) at lines [2, 3, 4]"]

    rag_context = [{
        'vulnerability_type': 'Reentrancy',
        'description': 'Classic DAO attack pattern',
        'code': 'External call before state update',
        'similarity': 0.92
    }]

    result = llm.analyze(test_code, slither_warnings, rag_context)

    if result['success']:
        print("LLM Analysis:")
        print(result['analysis'])
        print(f"\nTokens used: {result['prompt_tokens']} + {result['completion_tokens']}")
    else:
        print(f"Error: {result['error']}")
