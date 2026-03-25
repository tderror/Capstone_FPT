from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List
from collections import Counter
import asyncio
import re
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import modules
from ast_parser import SolidityASTParser
from smart_rag_system import SmartRAGSystem  # v6 - CodeRankEmbed + Qdrant + Reranker + CRAG
from llm_analyzer import LLMAnalyzer

def _infer_filter_type(code: str) -> str:
    """Infer the most likely vulnerability type from Solidity code patterns.

    Used to pass metadata filter to Qdrant, reducing noise in retrieval results.
    Returns: "Reentrancy" | "UncheckedReturnValue" | None
    """
    # .call{value:} or .call.value() → classic reentrancy pattern
    if re.search(r'\.call\{value:', code) or re.search(r'\.call\.value', code):
        return "Reentrancy"
    # .send() or bare .call() without value → unchecked return value
    if re.search(r'\.send\(', code) or re.search(r'\.call\(', code):
        return "UncheckedReturnValue"
    return None


app = FastAPI(
    title="DarkHotel Smart Contract Analyzer",
    version="6.0.0",
    description="AI-powered Solidity vulnerability detection: 6-Step Pipeline (AST tree-sitter -> Slither + RAG -> Cross-Encoder Rerank + CRAG Gate -> LLM CoT -> JSON Report)"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Config from Environment Variables ---
API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("GEMINI_API_KEY not found in environment variables! Create .env file with GEMINI_API_KEY=your_key")

MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-pro")
QDRANT_DB_PATH = os.getenv("QDRANT_DB_PATH", "./qdrant_db_v7")

# Initialize modules (once at server start)
print("[INIT] Initializing DarkHotel v6.0...")
print(f"[INIT] Model: {MODEL_NAME}")
print("[INIT] Pipeline: AST (tree-sitter) -> Slither + RAG (parallel) -> Cross-Encoder Rerank + CRAG Gate -> LLM CoT -> JSON Report")
ast_parser = SolidityASTParser()
from slither_smart_wrapper import SmartSlitherWrapper
slither = SmartSlitherWrapper()
smart_rag = SmartRAGSystem(persist_directory=QDRANT_DB_PATH)
llm = LLMAnalyzer(api_key=API_KEY, model=MODEL_NAME)
rag_stats = smart_rag.get_stats()
print(f"[INIT] All modules ready! (tree-sitter + Slither + RAG v6 [{rag_stats['total_cases']} cases] + CodeRankEmbed + {MODEL_NAME})")


@app.get("/")
async def root():
    """Health check endpoint with system information"""
    stats = smart_rag.get_stats()
    return {
        "status": "online",
        "version": "6.0.0",
        "pipeline": "AST (tree-sitter) -> Slither + RAG (parallel) -> Cross-Encoder Rerank + CRAG Gate -> LLM CoT -> JSON Report",
        "model": MODEL_NAME,
        "modules": {
            "ast_parser": f"ready (tree-sitter: {ast_parser.ts_available})",
            "slither": "ready (Smart Wrapper)",
            "smart_rag": f"ready ({stats['total_cases']} cases, {stats['version']})",
            "embedding": f"ready ({stats.get('embedding', 'CodeRankEmbed')})",
            "reranker": f"ready ({stats.get('reranker', 'ms-marco-MiniLM')})",
            "crag": f"ready ({stats.get('crag', 'CRAG evaluator')})",
            "vector_db": f"ready ({stats.get('vector_db', 'Qdrant')})",
            "llm": f"ready ({MODEL_NAME})"
        }
    }


@app.post("/analyze")
async def analyze_contract(file: UploadFile = File(...)):
    """
    6-Step Pipeline v6.0

    1. AST Chunking (tree-sitter) - Extract function-level semantic chunks
    2. Slither Static Analysis (parallel with RAG)
    3. RAG Search - Per-function retrieval with CodeRankEmbed + Qdrant
    4. Cross-Encoder Reranking (ms-marco-MiniLM) + CRAG Gate (Correct/Ambiguous/Incorrect)
    5. LLM CoT Reasoning - Tri-partite prompt (code + slither + gated RAG evidence)
    6. Generate Report - Structured JSON output
    """
    print(f"\n{'='*60}")
    print(f"[PIPELINE v6.0] 6-Step Analysis")
    print(f"{'='*60}")

    try:
        # --- Validate file upload ---
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit

        # Check file extension
        if not file.filename or not file.filename.endswith(".sol"):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Only .sol (Solidity) files are accepted."
            )

        # Read uploaded file
        content = await file.read()

        # Check file size
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File too large ({len(content)} bytes). Maximum allowed: {MAX_FILE_SIZE // (1024*1024)}MB."
            )

        code_text = content.decode("utf-8")
        print(f"[INPUT] File: {file.filename}, Size: {len(content)} bytes")

        if not code_text.strip():
            raise HTTPException(status_code=400, detail="File is empty")

        # Basic Solidity syntax check (must contain pragma or contract/interface/library)
        if not re.search(r'pragma\s+solidity|contract\s+\w+|interface\s+\w+|library\s+\w+', code_text):
            raise HTTPException(
                status_code=400,
                detail="File does not appear to be a valid Solidity source file."
            )

        # === STEP 1: AST Chunking ===
        print("\n[STEP 1/6] AST Chunking - extracting functions...")
        ast_result = ast_parser.parse(code_text)
        ast_summary = ast_parser.get_summary(ast_result)
        function_chunks = ast_parser.get_function_chunks(ast_result)
        risky_functions = ast_parser.get_risky_functions(ast_result)

        print(f"   -> Solidity: {ast_summary['solidity_version']}")
        print(f"   -> Contracts: {ast_summary['total_contracts']}, Functions: {ast_summary['total_functions']}")
        print(f"   -> Risky functions: {len(risky_functions)}")
        print(f"   -> Parse method: {ast_summary.get('parse_method', 'unknown')}")

        # === STEP 2+3: Slither + RAG Search (PARALLEL) ===
        # Slither and RAG are independent — run concurrently to save time
        print("\n[STEP 2+3/6] Slither + RAG Search (parallel)...")

        # Define RAG search coroutine
        async def run_rag_search():
            rag_candidates = []
            if risky_functions:
                for func in risky_functions:
                    search_query = func['code']
                    # Fix #5: Infer filter_type from code patterns to reduce noise
                    filter_type = _infer_filter_type(func['code'])
                    # Fix #8: Request 15 candidates per function (reranker needs larger pool)
                    func_results = await asyncio.to_thread(
                        smart_rag.search_similar, search_query, 15, filter_type
                    )
                    for r in func_results:
                        r['source_function'] = func['name']
                        r['source_contract'] = func['contract']
                    rag_candidates.extend(func_results)
            else:
                search_query = code_text[:3000]
                rag_candidates = await asyncio.to_thread(
                    smart_rag.search_similar, search_query, 15, None
                )
            return rag_candidates

        # Run Slither + RAG in parallel
        slither_task = asyncio.to_thread(slither.get_warnings_for_ai, code_text)
        rag_task = run_rag_search()

        slither_warnings, rag_candidates = await asyncio.gather(
            slither_task, rag_task
        )

        # Extract Slither hints
        slither_hints = []
        for w in slither_warnings:
            if isinstance(w, str) and w.startswith('['):
                match = re.search(r'\]\s*([\w-]+)', w)
                if match:
                    slither_hints.append(match.group(1))

        # Map Slither detector names to human-readable vulnerability types
        HINT_TO_VULN = {
            "reentrancy-eth": "Reentrancy",
            "reentrancy-no-eth": "Reentrancy",
            "reentrancy-benign": "Reentrancy",
            "reentrancy-events": "Reentrancy",
            "unchecked-send": "Unchecked Return Value",
            "unchecked-lowlevel": "Unchecked Return Value",
            "unchecked-transfer": "Unchecked Return Value",
        }
        slither_vuln_types = list(set(
            HINT_TO_VULN[h] for h in slither_hints if h in HINT_TO_VULN
        ))

        print(f"   -> Slither: {len(slither_warnings)} warnings, hints: {slither_hints if slither_hints else 'none'}")
        print(f"   -> Slither vuln types: {slither_vuln_types if slither_vuln_types else 'none'}")
        print(f"   -> RAG: searched {len(risky_functions) if risky_functions else 'full contract'}")

        # Deduplicate by (vulnerability_type, swc_id, source_function, audit_company)
        # Fix #6: Relaxed from max 2 to max 3 per key — gives cross-encoder
        # reranker a larger pool so it can pick the best candidates itself
        dedup_count = Counter()
        unique_candidates = []
        for r in rag_candidates:
            key = (r.get('vulnerability_type'), r.get('swc_id'), r.get('source_function'), r.get('audit_company', ''))
            dedup_count[key] += 1
            if dedup_count[key] <= 3:
                unique_candidates.append(r)

        print(f"   -> Raw: {len(rag_candidates)}, Unique: {len(unique_candidates)}")

        # === STEP 4: Cross-Encoder Reranking + CRAG Gate ===
        print("\n[STEP 4/6] Cross-encoder reranking + CRAG gate...")

        # Build rerank query from risky functions.
        # Fix #3: ms-marco cross-encoder is NL-trained — emphasize NL description
        # over raw code. Include vulnerability context so cross-encoder can
        # measure genuine relevance instead of being confused by Solidity syntax.
        # Build Slither-enhanced context for reranking
        slither_context = ""
        if slither_vuln_types:
            slither_context = f" Slither detected: {', '.join(slither_vuln_types)}."

        if risky_functions:
            rerank_parts = []
            for func in risky_functions[:3]:  # Top 3 risky functions
                indicators = ", ".join(func.get('risk_indicators', []))
                inferred_type = _infer_filter_type(func.get('code', ''))
                vuln_hint = f" Suspected: {inferred_type}." if inferred_type else ""
                rerank_parts.append(
                    f"Smart contract security vulnerability in Solidity function "
                    f"{func['name']} of contract {func['contract']}. "
                    f"Risk indicators: {indicators}.{vuln_hint}{slither_context} "
                    f"This function involves external calls and state modifications "
                    f"that may lead to reentrancy, unchecked return values, or "
                    f"integer overflow exploits. "
                    f"Code: {func['code'][:200]}"
                )
            rerank_query = " | ".join(rerank_parts)
        else:
            # Fallback: no risky functions detected by AST.
            # Still build an NL query so cross-encoder can work properly.
            inferred = _infer_filter_type(code_text)
            vuln_hint = f" Suspected: {inferred}." if inferred else ""
            rerank_query = (
                f"Smart contract security audit of Solidity code.{vuln_hint}{slither_context} "
                f"Checking for reentrancy, unchecked return values, and integer overflow vulnerabilities. "
                f"Code: {code_text[:500]}"
            )

        # 4a: Cross-encoder reranking (ms-marco-MiniLM-L-6-v2)
        reranked_results = await asyncio.to_thread(
            smart_rag.reranker.rerank,
            rerank_query[:2000],
            unique_candidates,
            5
        )

        print(f"   -> {len(unique_candidates)} candidates -> {len(reranked_results)} reranked results")
        for i, r in enumerate(reranked_results):
            bi = r.get('bi_encoder_score', 0)
            ce = r.get('cross_encoder_score', 0)
            combined = r.get('combined_score', 0)
            print(f"      [{i+1}] {r.get('vulnerability_type', '?')} (bi={bi:.4f}, ce={ce:.4f}, combined={combined:.4f})")

        # 4b: CRAG evaluation (Corrective RAG)
        crag_action, gated_evidence = smart_rag.crag.evaluate(reranked_results)
        top_combined = reranked_results[0].get('combined_score', 0) if reranked_results else 0
        top_bi = reranked_results[0].get('bi_encoder_score', 0) if reranked_results else 0
        print(f"   -> CRAG gate: {crag_action} (top combined={top_combined:.4f}, top bi={top_bi:.4f})")

        if crag_action == "CORRECT":
            evidence_for_llm = gated_evidence
            print(f"   -> CRAG: CORRECT -> sending {len(evidence_for_llm)} evidence to LLM")
        elif crag_action == "AMBIGUOUS":
            evidence_for_llm = gated_evidence
            print(f"   -> CRAG: AMBIGUOUS -> sending {len(evidence_for_llm)} filtered evidence to LLM")
        else:
            evidence_for_llm = []
            print(f"   -> CRAG: INCORRECT -> LLM judges alone (no RAG evidence)")

        # === STEP 5: LLM Chain-of-Thought Reasoning ===
        print("\n[STEP 5/6] LLM Chain-of-Thought reasoning...")

        # Fix #7: Pass CRAG action to LLM so prompt adapts evidence framing
        llm_result = await asyncio.to_thread(
            llm.analyze,
            code_text,
            slither_warnings,
            evidence_for_llm,  # Gated: top-5 or empty
            use_advanced_prompt=True,
            solidity_version=ast_summary['solidity_version'],
            crag_action=crag_action
        )

        if not llm_result['success']:
            raise HTTPException(status_code=500, detail=f"LLM Error: {llm_result['error']}")

        print(f"   -> LLM completed ({llm_result.get('completion_tokens', 0)} tokens)")

        # === STEP 6: Generate Report ===
        print("\n[STEP 6/6] Generating report...")

        ai_raw = llm_result.get('analysis', '')
        ai_json = llm_result.get('analysis_json')

        # Determine RAG findings summary from reranked results + CRAG action
        rag_found = False
        rag_vuln_type = "No Vulnerabilities Detected"
        if reranked_results and crag_action in ("CORRECT", "AMBIGUOUS"):
            top_result = reranked_results[0]
            vuln_type = top_result.get('vulnerability_type', 'Unknown')
            if vuln_type not in ['NonVulnerable', 'Safe', 'Secure']:
                rag_found = True
                rag_vuln_type = f"{vuln_type} ({top_result.get('swc_id', 'N/A')})"

        response = {
            "success": True,
            "filename": file.filename,
            "pipeline_version": "6.0-6step",

            # AI Analysis - raw text (backward compat) + structured JSON
            "ai_analysis": ai_raw,
            "ai_analysis_structured": ai_json,

            # RAG Findings
            "rag_findings": {
                "found": rag_found,
                "vuln_type": rag_vuln_type,
                "crag_action": crag_action,
                "similar_cases": [
                    {
                        "type": case.get('vulnerability_type', 'Unknown'),
                        "swc_id": case.get('swc_id', 'N/A'),
                        "severity": case.get('severity', 'Unknown'),
                        "bi_encoder_score": case.get('bi_encoder_score', case.get('similarity', 0)),
                        "cross_encoder_score": case.get('cross_encoder_score', 0),
                        "combined_score": case.get('combined_score', 0),
                        "function": case.get('function', 'N/A'),
                        "line_number": case.get('line_number', 'N/A'),
                        "audit_company": case.get('audit_company', 'N/A'),
                        "source_file": case.get('source_file', 'N/A'),
                        "source_function": case.get('source_function', None),
                    }
                    for case in reranked_results
                ],
                "total_candidates": len(unique_candidates),
                "top_k_ranked": len(reranked_results),
                "version": "v6.0-qdrant-coderankembed"
            },

            # Function-level analysis
            "function_analysis": {
                "total_functions": ast_summary['total_functions'],
                "risky_functions": len(risky_functions),
                "functions_analyzed": [
                    {
                        "name": f['name'],
                        "contract": f['contract'],
                        "risk_indicators": f['risk_indicators'],
                        "has_external_call": f['has_external_call'],
                        "has_state_change": f['has_state_change'],
                        "modifiers": f['modifiers']
                    }
                    for f in risky_functions
                ]
            },

            # Summary
            "summary": {
                "total_lines": len(code_text.split('\n')),
                "total_functions": ast_summary['total_functions'],
                "solidity_version": ast_summary['solidity_version'],
                "functions": [f['name'] for f in function_chunks]
            },

            # Slither Analysis
            "slither_analysis": {
                "warnings": slither_warnings,
                "hints_used": slither_hints,
                "total_warnings": len(slither_warnings)
            },

            # LLM Metadata
            "llm_analysis": {
                "verdict": ai_json.get('verdict', 'UNKNOWN') if ai_json else "See ai_analysis",
                "model": llm_result['model'],
                "tokens": {
                    "prompt": llm_result.get('prompt_tokens', 0),
                    "completion": llm_result.get('completion_tokens', 0)
                }
            }
        }

        print(f"\n[DONE] Analysis complete!")
        print(f"{'='*60}\n")

        return response

    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not valid UTF-8 text")
    except Exception as e:
        print(f"\nError: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))