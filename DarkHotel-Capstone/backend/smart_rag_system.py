"""
Smart RAG System v6 - DarkHotel
================================
Knowledge-level RAG with:
- CodeRankEmbed (nomic-ai, 137M, 768d) for code embedding
- Qdrant (local mode) for vector search
- ms-marco-MiniLM-L-12-v2 cross-encoder for reranking
- CRAG (Corrective RAG) evaluator for retrieval quality gating
"""

import os
import sys
from typing import Dict, List, Optional
import numpy as np
from sentence_transformers import SentenceTransformer, CrossEncoder
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, Filter, FieldCondition, MatchValue
from dotenv import load_dotenv

# Fix Windows encoding
if sys.stdout:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

load_dotenv()

# --- CONFIG ---
QDRANT_PATH = "./qdrant_db_v7"
COLLECTION_NAME = "darkhotel_v7"


# =============================================================================
# EMBEDDING: CodeRankEmbed (Nomic AI, ICLR 2025)
# =============================================================================

class CodeRankEmbeddings:
    """
    CodeRankEmbed - 137M param code embedding model.
    Trained on CoRNStack (21M code examples).
    768 dimensions, Apache-2.0, runs on CPU.

    Paper: Suresh et al., ICLR 2025 (arXiv:2412.01007)
    """

    def __init__(self, model_name: str = "nomic-ai/CodeRankEmbed"):
        self.model = SentenceTransformer(model_name, trust_remote_code=True)
        self.model.max_seq_length = 8192
        self.dimension = 768

    def embed_query(self, text: str) -> List[float]:
        """Embed a search query (uses 'search_query:' prefix per model card)"""
        prefixed = f"search_query: {text}"
        return self.model.encode([prefixed], show_progress_bar=False)[0].tolist()

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple documents"""
        prefixed = [f"search_document: {t}" for t in texts]
        return self.model.encode(prefixed, show_progress_bar=False).tolist()


# =============================================================================
# CROSS-ENCODER RERANKER: ms-marco-MiniLM-L-12-v2
# =============================================================================

class RelevanceReranker:
    """
    Cross-encoder reranker using ms-marco-MiniLM-L-12-v2 (33M params).
    Scores (query, document) pairs jointly for fine-grained relevance.
    L-12 provides better accuracy than L-6 with minimal latency increase.
    """

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-12-v2"):
        self.cross_encoder = CrossEncoder(model_name)

    def rerank(self, query: str, candidates: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        Rerank candidates using cross-encoder scores.

        Returns top_k candidates with both bi-encoder and cross-encoder scores.
        Final score = 0.4 * bi_encoder + 0.6 * cross_encoder (cross-encoder weighted higher).
        """
        if not candidates:
            return []

        # Build (query, document) pairs
        pairs = []
        for c in candidates:
            doc_text = self._build_doc_text(c)
            pairs.append((query[:2000], doc_text[:2000]))  # Truncate for efficiency

        # Score with cross-encoder
        scores = self.cross_encoder.predict(pairs)

        # Normalize cross-encoder scores to 0-1 range using sigmoid
        # Sigmoid is stable regardless of score distribution (works for 1 candidate or many)
        norm_scores = [float(1.0 / (1.0 + np.exp(-float(s)))) for s in scores]

        # Attach scores — keep original similarity (bi-encoder cosine) intact
        for i, c in enumerate(candidates):
            c["bi_encoder_score"] = c.get("similarity", 0)
            c["cross_encoder_score"] = norm_scores[i]
            c["combined_score"] = round(
                0.4 * c["bi_encoder_score"] + 0.6 * c["cross_encoder_score"], 4
            )

        return sorted(candidates, key=lambda x: x["combined_score"], reverse=True)[:top_k]

    def _build_doc_text(self, candidate: Dict) -> str:
        """Build text representation of a candidate for cross-encoder.

        Format matches the NL+code style used in rerank queries so that
        ms-marco cross-encoder can measure genuine relevance.
        """
        parts = []
        vtype = candidate.get("vulnerability_type", "")
        swc = candidate.get("swc_id", "")
        if vtype:
            parts.append(f"Solidity vulnerability: {vtype} ({swc})")
        func = candidate.get("function", "")
        if func:
            parts.append(f"in function {func}")
        root = candidate.get("root_cause", "")
        if root:
            parts.append(f"Root cause: {root}")
        trigger = candidate.get("trigger_condition", "")
        if trigger:
            parts.append(f"Trigger: {trigger}")
        fix = candidate.get("fix_solution", "")
        if fix:
            parts.append(f"Fix: {fix}")
        code = candidate.get("code_snippet_vulnerable", "")
        if code:
            parts.append(f"Code: {code[:400]}")
        return ". ".join(parts) if parts else str(candidate)


# =============================================================================
# CRAG EVALUATOR (Corrective Retrieval Augmented Generation)
# =============================================================================

class CRAGEvaluator:
    """
    Corrective RAG evaluator based on Yan et al. (arXiv:2401.15884).

    Uses cross-encoder relevance scores to determine retrieval quality:
    - CORRECT (score >= 0.7): Retrieved evidence is highly relevant, pass to LLM
    - AMBIGUOUS (0.3 <= score < 0.7): Partially relevant, pass filtered evidence
    - INCORRECT (score < 0.3): Irrelevant retrieval, discard and let LLM judge alone

    This replaces the simple threshold gate and provides principled quality control.
    """

    CORRECT_THRESHOLD = 0.7
    INCORRECT_THRESHOLD = 0.3

    def evaluate(self, candidates: List[Dict]) -> tuple:
        """
        Evaluate retrieval quality and determine action.

        Decision logic (evaluated top-down, first match wins):

        1. Bi-encoder floor: if CodeRankEmbed (code-specialist) gives high
           confidence (bi >= 0.75) but combined_score is low (cross-encoder
           disagrees), trust the code model and preserve as AMBIGUOUS.
           This prevents the NL cross-encoder from discarding code-relevant results.

        2. Combined score >= 0.7 → CORRECT (high confidence from both models)
        3. Combined score >= 0.3 → AMBIGUOUS (partial relevance)
        4. Otherwise → INCORRECT (discard, LLM judges alone)

        Args:
            candidates: Reranked candidates (must have 'combined_score' and
                        'bi_encoder_score' fields from RelevanceReranker)

        Returns:
            (action, filtered_candidates):
                action: "CORRECT" | "AMBIGUOUS" | "INCORRECT"
                filtered_candidates: evidence to pass to LLM (may be empty)
        """
        if not candidates:
            return "INCORRECT", []

        top_combined = candidates[0].get("combined_score", 0)
        top_bi = candidates[0].get("bi_encoder_score", 0)
        top_ce = candidates[0].get("cross_encoder_score", 0)

        # Bi-encoder floor: CodeRankEmbed is code-specialized (21M code examples).
        # If it says "highly relevant" (bi >= 0.75) but the NL cross-encoder
        # scored low (ce < 0.3), the cross-encoder likely doesn't understand the
        # code similarity. Preserve evidence as AMBIGUOUS instead of dropping.
        # We check cross_encoder_score directly (not combined_score) because
        # combined = 0.4*bi + 0.6*ce is always >= 0.3 when bi >= 0.75,
        # making a combined_score check unreachable (dead code).
        if top_bi >= 0.75 and top_ce < 0.3:
            filtered = [
                c for c in candidates
                if c.get("bi_encoder_score", 0) >= 0.6
            ]
            return "AMBIGUOUS", filtered

        if top_combined >= self.CORRECT_THRESHOLD:
            return "CORRECT", candidates

        elif top_combined >= self.INCORRECT_THRESHOLD:
            filtered = [
                c for c in candidates
                if c.get("combined_score", 0) >= self.INCORRECT_THRESHOLD
            ]
            return "AMBIGUOUS", filtered

        else:
            return "INCORRECT", []


# =============================================================================
# SMART RAG SYSTEM v6
# =============================================================================

class SmartRAGSystem:
    """
    Smart RAG System v6 - Knowledge-level RAG for Smart Contract Vulnerability Detection

    Components:
    - CodeRankEmbed (137M, 768d) for code-specialized embedding
    - Qdrant (local mode) for vector similarity search with metadata filtering
    - ms-marco-MiniLM-L-12 cross-encoder for reranking
    - CRAG evaluator for retrieval quality gating

    v6 Updates:
    - Replaced UniXcoder with CodeRankEmbed (ICLR 2025)
    - Replaced ChromaDB with Qdrant local mode
    - Added cross-encoder reranking (ms-marco-MiniLM-L-12-v2)
    - Added CRAG evaluator (Correct/Ambiguous/Incorrect actions)
    - Knowledge-enriched KB with root_cause, trigger_condition, fix_solution
    """

    def __init__(self, persist_directory: str = QDRANT_PATH):
        print(f"[SmartRAG v6] Initializing...")

        self.persist_directory = persist_directory
        self.kb_version = "v7"

        # 1. CodeRankEmbed embedding model
        print(f"[SmartRAG v6] Loading CodeRankEmbed embedding model...")
        self.embedding = CodeRankEmbeddings()

        # 2. Qdrant vector database (local mode, no Docker)
        print(f"[SmartRAG v6] Connecting to Qdrant at {persist_directory}...")
        self.qdrant = QdrantClient(path=persist_directory)

        # Check collection
        collections = [c.name for c in self.qdrant.get_collections().collections]
        if COLLECTION_NAME in collections:
            info = self.qdrant.get_collection(COLLECTION_NAME)
            self.total_entries = info.points_count
            self.kb_version = "v7-knowledge-enriched"
            print(f"[SmartRAG v6] KB Connected: {self.total_entries} entries")
        else:
            self.total_entries = 0
            print(f"[SmartRAG v6] WARNING: Collection '{COLLECTION_NAME}' not found. Run migrate_to_qdrant.py first.")

        # 3. Cross-encoder reranker
        print(f"[SmartRAG v6] Loading cross-encoder reranker...")
        self.reranker = RelevanceReranker()

        # 4. CRAG evaluator
        self.crag = CRAGEvaluator()

        print(f"[SmartRAG v6] Ready!")

    def get_stats(self) -> Dict:
        """Return stats for health check"""
        categories = [
            "SWC-107 Reentrancy (129)",
            "SWC-101 Integer Overflow (173)",
            "SWC-104 Unchecked Call Return Value (105)",
        ]
        return {
            "total_cases": self.total_entries,
            "version": self.kb_version,
            "collection": COLLECTION_NAME,
            "categories": categories,
            "source": "DAppSCAN (608 professional audits, v7-quality-fixed)",
            "embedding": "CodeRankEmbed (nomic-ai, 768d)",
            "vector_db": "Qdrant (local mode)",
            "reranker": "ms-marco-MiniLM-L-12-v2",
            "crag": "Cross-encoder CRAG evaluator",
        }

    # ─── Vector Search ────────────────────────────────────────────────

    def search_similar(self, code: str, top_k: int = 5, filter_type: str = None) -> List[Dict]:
        """
        Search for similar vulnerability cases in Qdrant.

        Args:
            code: Solidity code to search for
            top_k: Number of results to return
            filter_type: Optional filter: "Reentrancy" | "IntegerUO" | "UncheckedReturnValue"

        Returns:
            List of dicts with vulnerability_type, swc_id, severity, similarity, etc.
        """
        if self.total_entries == 0:
            return []

        try:
            query_vector = self.embedding.embed_query(code)

            # Build Qdrant filter
            qdrant_filter = None
            if filter_type:
                swc_name_map = {
                    "Reentrancy": "Reentrancy",
                    "IntegerUO": "Integer Overflow and Underflow",
                    "UncheckedReturnValue": "Unchecked Call Return Value",
                }
                mapped = swc_name_map.get(filter_type, filter_type)
                qdrant_filter = Filter(must=[
                    FieldCondition(key="swc_name", match=MatchValue(value=mapped))
                ])

            # Retrieve with relaxed threshold — let cross-encoder reranker
            # decide relevance instead of hard-filtering at bi-encoder stage.
            # Old threshold 0.3 was too aggressive: code with different structure
            # but same vulnerability pattern (e.g., overflow in loop vs in transfer)
            # could score below 0.3 in cosine similarity but still be relevant.
            query_result = self.qdrant.query_points(
                collection_name=COLLECTION_NAME,
                query=query_vector,
                limit=top_k,
                query_filter=qdrant_filter,
                with_payload=True,
                score_threshold=0.15,
            )
            results = query_result.points

            formatted = []
            for point in results:
                p = point.payload
                formatted.append({
                    "vulnerability_type": p.get("swc_name", "Unknown"),
                    "swc_id": p.get("swc_id", "N/A"),
                    "severity": p.get("severity", "Unknown"),
                    "similarity": round(float(point.score), 4),
                    "function": p.get("function", "N/A"),
                    "line_number": p.get("line_number", "N/A"),
                    "audit_company": p.get("audit_company", "N/A"),
                    "code_snippet_vulnerable": p.get("code_snippet_vulnerable", ""),
                    "source_file": p.get("source_file", "N/A"),
                    "root_cause": p.get("root_cause", ""),
                    "trigger_condition": p.get("trigger_condition", ""),
                    "fix_solution": p.get("fix_solution", ""),
                })

            formatted = sorted(formatted, key=lambda x: x["similarity"], reverse=True)
            print(f"[SmartRAG v6] Bi-encoder retrieved: {len(formatted)} results")

            return formatted

        except Exception as e:
            print(f"[SmartRAG v6] Search error: {e}")
            return []


if __name__ == "__main__":
    rag = SmartRAGSystem()
    stats = rag.get_stats()
    print(f"Stats: {stats}")
