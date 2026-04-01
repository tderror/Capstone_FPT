"""
Advanced LLM Analyzer với Chain-of-Thought Prompting
Using Google GenAI SDK via Vertex AI
"""
from google import genai
from google.genai.types import HttpOptions
import json
import re
import time
from typing import Dict, List
import os

class LLMAnalyzer:
    """
    Wrapper cho LLM analysis với advanced prompting techniques
    Using Google GenAI SDK via Vertex AI
    """

    def __init__(self, project: str, location: str = "us-central1",
                 model: str = "gemini-2.5-pro"):
        self.project = project
        self.location = location
        self.model = model

        # Initialize GenAI client with Vertex AI
        self.client = genai.Client(
            http_options=HttpOptions(api_version="v1beta1"),
            vertexai=True,
            project=project,
            location=location,
        )

        self.max_retries = 5
        self.retry_delay = 60

    def _build_rag_knowledge_section(self, rag_context: List[Dict], crag_action: str) -> str:
        """
        Build RAG evidence section + Tier 2 expert rules derived from audit knowledge base.

        Tier 2 rules (safe-pattern recognition, severity calibration, exploit templates)
        are ONLY available when RAG provides evidence. Without RAG, LLM only has
        Tier 1 basic detection rules — this creates measurable RAG contribution.
        """
        if not rag_context or rag_context[0].get('vulnerability_type') == 'No data':
            return (
                "## HISTORICAL CASES:\n"
                "No similar cases found in the audit knowledge base.\n"
                "You have NO expert rules from historical audits — rely entirely on your own analysis.\n"
                "Without expert rules, you are MORE LIKELY to produce false positives.\n"
                "For each finding: you MUST still check all 3 vulnerability types, but ONLY report\n"
                "a vulnerability if you can provide a CONCRETE exploit scenario with specific\n"
                "function names, line numbers, and step-by-step attacker actions.\n"
                "If you cannot construct a concrete exploit, mark it SAFE.\n"
            )

        # --- RAG evidence cases ---
        if crag_action == "CORRECT":
            section = (
                "## HISTORICAL CASES (HIGH-CONFIDENCE match from audit knowledge base):\n"
                "These cases were evaluated as HIGHLY RELEVANT by the retrieval quality gate.\n"
                "Use them as your PRIMARY analysis framework — the code patterns are very similar.\n"
                "You MUST reference these cases in your reasoning.\n\n"
            )
        elif crag_action == "AMBIGUOUS":
            section = (
                "## HISTORICAL CASES (PARTIAL match from audit knowledge base):\n"
                "These cases are PARTIALLY RELEVANT. Use them as supplementary context.\n"
                "Apply the expert rules below but verify each against the current code.\n\n"
            )
        else:
            section = "## HISTORICAL CASES (from audit knowledge base):\n"

        for i, case in enumerate(rag_context[:3], 1):
            code_snippet = case.get('code_snippet_vulnerable', '')
            swc_id = case.get('swc_id', '')
            severity = case.get('severity', '')
            audit = case.get('audit_company', '')
            root_cause = case.get('root_cause', '')
            trigger = case.get('trigger_condition', '')
            fix = case.get('fix_solution', '')
            score = case.get('relevance_score', case.get('similarity', 0))

            section += f"""
### Case {i}: {case.get('vulnerability_type', 'Unknown')} {f'({swc_id})' if swc_id else ''} - Relevance: {score:.2f}
**Severity**: {severity}
**Function**: {case.get('function', 'N/A')} @ {case.get('line_number', 'N/A')}
**Audit**: {audit}
"""
            if root_cause:
                section += f"**Root Cause**: {root_cause}\n"
            if trigger:
                section += f"**Trigger Condition**: {trigger}\n"
            if fix:
                section += f"**Fix Solution**: {fix}\n"
            section += f"""**Vulnerable Code**:
```solidity
{code_snippet}
```
"""

        # --- Tier 2: Expert rules from audit knowledge base ---
        # These rules are ONLY injected when RAG evidence is available.
        # Without RAG, LLM does NOT have these rules → higher FP rate.
        section += """
## EXPERT RULES FROM AUDIT KNOWLEDGE BASE:
The following rules are derived from 407 real audit cases in our knowledge base.
Apply these rules to distinguish VULNERABLE from SAFE patterns:

### Safe Pattern Recognition (DO NOT report if these protections exist):

**Reentrancy (SWC-107) — Safe patterns:**
- `.send()` and `.transfer()` forward only 2300 gas — insufficient for reentrancy callback. Do NOT report SWC-107 for these.
- ReentrancyGuard / `nonReentrant` modifier completely prevents reentrancy. Do NOT report.
- Checks-Effects-Interactions (CEI) pattern: state updated BEFORE external call. Do NOT report.
- Mutex/lock pattern (`bool locked; require(!locked); locked = true; ...; locked = false`). Do NOT report.
- ERC20/IERC20 token calls (`.transfer()`, `.transferFrom()`, `.approve()`) are HIGH-LEVEL interface calls, NOT raw `.call{value:}()`. They CANNOT cause reentrancy. Do NOT report SWC-107 for ERC20 token operations.

**Integer Overflow (SWC-101) — Safe patterns:**
- Solidity >= 0.8.0 has BUILT-IN overflow/underflow protection that auto-reverts. SWC-101 is IMPOSSIBLE for ^0.8.x. This is ABSOLUTE — no exceptions.
- SafeMath library wraps arithmetic with overflow checks. Do NOT report if SafeMath is used.
- Arithmetic on non-critical values (loop counters, timestamps, array indices, display values) has no exploitable impact. Do NOT report.
- Bounded inputs (e.g., percentage * amount where percentage <= 100) cannot realistically overflow.

**Unchecked Return Value (SWC-104) — Safe patterns:**
- `.transfer()` auto-reverts on failure — no return check needed. Do NOT report.
- Return value captured in bool and checked with `require()` or `if()`. Do NOT report.
- ERC20 `.transfer()` and `.transferFrom()` are high-level calls with built-in revert — NOT the same as low-level `.call()`. Do NOT report SWC-104 for ERC20 operations.

### Severity Calibration (from historical audit data):
- Full fund drain via reentrancy → Critical
- Reentrancy with capped/limited re-enterable amount → Medium (not Critical)
- Integer overflow affecting balances/supply/auth → High
- Integer overflow on bounded arithmetic (price * small_qty) → Medium or Low
- Unchecked .send() on main withdrawal → High
- Unchecked .send() on refund of excess only → Medium
- If a finding has severity Low → consider NOT reporting (noise reduction)

### Exploit Verification (from historical trigger conditions):
- Only report a vulnerability if you can describe a CONCRETE exploit scenario
- The exploit must be triggerable by an external attacker (not just theoretical)
- Reference the trigger conditions from historical cases above when applicable
"""
        return section

    def create_advanced_prompt(
        self,
        code: str,
        slither_warnings: List[str],
        rag_context: List[Dict],
        crag_action: str = None
    ) -> str:
        """
        Tạo prompt với Chain-of-Thought reasoning + Prompt Tiering.

        Architecture:
        - Tier 1 (always present): Basic vulnerability detection checklist.
          LLM knows WHAT to check but has minimal guidance on safe vs vulnerable.
        - Tier 2 (from RAG only): Expert rules for safe-pattern recognition,
          severity calibration, exploit verification. Injected via
          _build_rag_knowledge_section() ONLY when RAG evidence is available.

        This creates measurable RAG contribution:
        - LLM alone (Tier 1 only): Can detect obvious vulns but HIGH false positive rate
        - LLM + RAG (Tier 1 + Tier 2): Accurate detection with LOW false positive rate

        Args:
            code: Original Solidity code
            slither_warnings: Warnings from Slither
            rag_context: Similar cases from RAG
            crag_action: CRAG gate result ("CORRECT"|"AMBIGUOUS"|"INCORRECT"|None)

        Returns:
            Formatted prompt string
        """

        # Build RAG section with Tier 2 expert rules (only when evidence available)
        rag_section = self._build_rag_knowledge_section(rag_context, crag_action)

        # Format Slither warnings
        slither_section = "## STATIC ANALYSIS (Slither):\n"
        if slither_warnings and len(slither_warnings) > 0:
            first_warning = slither_warnings[0]

            if first_warning.startswith('⚠️ SLITHER UNAVAILABLE'):
                slither_section += f"{first_warning}\n\n"
                slither_section += "**IMPORTANT:** You MUST perform thorough manual code review.\n"
                slither_section += "Rely heavily on RAG similar cases and your own analysis.\n"

            elif first_warning.startswith('['):
                slither_section += "**CRITICAL WARNINGS FOUND:**\n"
                for warning in slither_warnings:
                    slither_section += f"  {warning}\n"
                slither_section += "\n⚠️ PAY SPECIAL ATTENTION to these line numbers!\n"

            elif first_warning == "No vulnerabilities detected by Slither":
                slither_section += "- Slither found no vulnerabilities\n"
                slither_section += "- BUT: Slither has high false negative rate!\n"
                slither_section += "- STILL check code carefully using the expert rules above.\n"

            else:
                for warning in slither_warnings:
                    slither_section += f"- {warning}\n"
        else:
            slither_section += "- No Slither analysis available\n"

        # =====================================================================
        # PROMPT: Tier 1 (basic checklist) + Tier 2 (RAG expert rules above)
        # =====================================================================
        prompt = f"""You are an expert blockchain security auditor. Your task is to SYSTEMATICALLY check the Solidity code for the following 3 vulnerability types.

{slither_section}

{rag_section}

## CODE TO ANALYZE:
```solidity
{code}
```

## VULNERABILITY CHECKLIST (Tier 1 — Basic Detection):

You MUST check ALL 3 vulnerability types below. For EACH type, explicitly state YES or NO with evidence.
If EXPERT RULES FROM AUDIT KNOWLEDGE BASE are provided above, you MUST apply them to reduce false positives.

### 1. REENTRANCY (SWC-107)
- Check: Are there external calls BEFORE state updates?
- VULNERABLE: State changes happen AFTER external calls (`.call{{value:}}()`)
- If expert rules are available above, apply the safe pattern recognition rules before reporting.
- Answer: [YES/NO] with evidence

### 2. INTEGER OVERFLOW/UNDERFLOW (SWC-101)
- Check: What is the pragma solidity version? Are there unprotected arithmetic operations?
- VULNERABLE: Solidity < 0.8.0 + no SafeMath + arithmetic affects critical values
- If expert rules are available above, apply them to determine if the overflow is exploitable.
- Answer: [YES/NO] with evidence

### 3. UNCHECKED RETURN VALUE (SWC-104)
- Check: Are low-level calls used without checking the return value?
- VULNERABLE: `.send()` or `.call()` without `require()` or `if()` check
- If expert rules are available above, apply safe pattern recognition before reporting.
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
  "reasoning": "Your step-by-step Chain-of-Thought analysis covering all 3 vulnerability checks above. If expert rules were provided, explain how you applied them."
}}

If no vulnerabilities found, return:
{{
  "verdict": "SAFE",
  "confidence": "HIGH",
  "primary_vulnerability": null,
  "secondary_warnings": [],
  "vulnerabilities": [],
  "reasoning": "Explanation of why code is safe, referencing each check and expert rules if available"
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

        # Strategy 3: Find outermost JSON object using brace matching.
        # Simple find/rfind can fail when the LLM wraps the JSON in extra text
        # containing braces (e.g., example JSON in reasoning). Instead, find
        # the first '{' and then match braces to find its closing '}'.
        start = text.find('{')
        if start != -1:
            depth = 0
            in_string = False
            escape_next = False
            for i in range(start, len(text)):
                ch = text[i]
                if escape_next:
                    escape_next = False
                    continue
                if ch == '\\' and in_string:
                    escape_next = True
                    continue
                if ch == '"' and not escape_next:
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(text[start:i + 1])
                            except (json.JSONDecodeError, ValueError):
                                pass
                            break

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
        solidity_version: str = None,
        crag_action: str = None
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
            prompt = self.create_advanced_prompt(code, slither_warnings, rag_context, crag_action)
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

        # No system prefix needed — role is already defined in the prompt itself.
        # Adding "Output ONLY valid JSON" as a short reminder at the top.
        full_prompt = "IMPORTANT: Output ONLY valid JSON — no markdown, no commentary.\n\n" + prompt

        # Retry logic with exponential backoff
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    wait_time = self.retry_delay * (2 ** (attempt - 1))
                    print(f"\n[RETRY] Attempt {attempt + 1}/{self.max_retries} after {wait_time}s...")
                    time.sleep(wait_time)

                # Use GenAI SDK via Vertex AI
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
                    usage = response.usage_metadata
                    prompt_tokens = getattr(usage, 'prompt_token_count', 0) or 0
                    completion_tokens = getattr(usage, 'candidates_token_count', 0) or 0

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
    # Cần Google Cloud Project để test
    # Set GOOGLE_APPLICATION_CREDENTIALS trước khi chạy
    PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "")
    LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")

    llm = LLMAnalyzer(project=PROJECT_ID, location=LOCATION)

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
