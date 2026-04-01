"""
Smart RAG System v7 - DarkHotel
================================
Knowledge-level RAG with:
- voyage-code-3 (Voyage AI, 1024d) for code embedding
- Qdrant (local mode) for vector search
- voyage-rerank-2.5 (Voyage AI) for instruction-following reranking
- CRAG (Corrective RAG) evaluator for retrieval quality gating
"""

import os
import sys
from typing import Dict, List, Optional
import voyageai
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
QDRANT_PATH = "./qdrant_db_v8"
COLLECTION_NAME = "darkhotel_v8"


# =============================================================================
# EMBEDDING: voyage-code-3 (Voyage AI)
# =============================================================================

class VoyageCodeEmbeddings:
    """
    voyage-code-3 - Code-specialized embedding model by Voyage AI.
    Trained on code + NL pairs across 300+ programming languages.
    Supports text-to-code, code-to-code, and docstring-to-code retrieval.
    Default 1024d, supports 256/512/1024/2048. Context: 32K tokens.
    """

    def __init__(self, model_name: str = "voyage-code-3", dimension: int = 1024):
        api_key = os.getenv("VOYAGE_API_KEY")
        if not api_key:
            raise ValueError(
                "VOYAGE_API_KEY not found in environment variables! "
                "Get your key at https://dash.voyageai.com/"
            )
        self.client = voyageai.Client(api_key=api_key)
        self.model_name = model_name
        self.dimension = dimension

    def embed_query(self, text: str) -> List[float]:
        """Embed a search query (input_type='query' per Voyage API)"""
        result = self.client.embed(
            texts=[text[:16000]],
            model=self.model_name,
            input_type="query",
            output_dimension=self.dimension,
        )
        return result.embeddings[0]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple documents (input_type='document').
        Auto-batches to stay within Voyage API limit (max 128 texts per request).
        """
        MAX_BATCH = 128
        truncated = [t[:16000] for t in texts]

        if len(truncated) <= MAX_BATCH:
            result = self.client.embed(
                texts=truncated,
                model=self.model_name,
                input_type="document",
                output_dimension=self.dimension,
            )
            return result.embeddings

        # Batch large requests
        all_embeddings = []
        for i in range(0, len(truncated), MAX_BATCH):
            batch = truncated[i:i + MAX_BATCH]
            result = self.client.embed(
                texts=batch,
                model=self.model_name,
                input_type="document",
                output_dimension=self.dimension,
            )
            all_embeddings.extend(result.embeddings)
        return all_embeddings


# =============================================================================
# RERANKER: voyage-rerank-2.5 (Voyage AI)
# =============================================================================

class VoyageReranker:
    """
    voyage-rerank-2.5 - Instruction-following reranker by Voyage AI.
    Returns relevance_score [0, 1] directly (no normalization needed).
    Supports 32K context per document, up to 1000 documents per request.
    Code-aware: understands Solidity/code semantics (unlike ms-marco NL-only).
    Supports instruction-following via query prefix.
    """

    def __init__(self, model_name: str = "rerank-2.5"):
        api_key = os.getenv("VOYAGE_API_KEY")
        if not api_key:
            raise ValueError(
                "VOYAGE_API_KEY not found in environment variables! "
                "Get your key at https://dash.voyageai.com/"
            )
        self.client = voyageai.Client(api_key=api_key)
        self.model_name = model_name

    def rerank(self, query: str, candidates: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        Rerank candidates using voyage-rerank-2.5.

        Returns top_k candidates with relevance_score [0, 1] from Voyage API.
        No normalization needed — scores are pre-calibrated:
        - 0.8-1.0: Highly relevant
        - 0.5-0.8: Moderately relevant
        - 0.0-0.5: Less relevant
        """
        if not candidates:
            return []

        # Build document texts for reranking
        documents = [self._build_doc_text(c) for c in candidates]

        # Prepend instruction for instruction-following reranker
        instructed_query = (
            "Find Solidity smart contract vulnerability patterns matching this code. "
            "Focus on reentrancy, integer overflow, and unchecked return values.\n\n"
            + query[:8000]
        )

        # Call Voyage rerank API
        reranking = self.client.rerank(
            query=instructed_query,
            documents=documents,
            model=self.model_name,
            top_k=top_k,
        )

        # Map results back to candidates with scores
        for result in reranking.results:
            idx = result.index
            candidates[idx]["relevance_score"] = result.relevance_score
            candidates[idx]["bi_encoder_score"] = candidates[idx].get("similarity", 0)

        # Sort by relevance_score and return top_k
        scored = [c for c in candidates if "relevance_score" in c]
        scored.sort(key=lambda x: x["relevance_score"], reverse=True)
        return scored[:top_k]

    def _build_doc_text(self, candidate: Dict) -> str:
        """Build text representation of a candidate for reranker."""
        parts = []
        vtype = candidate.get("vulnerability_type", "")
        swc = candidate.get("swc_id", "")
        if vtype:
            parts.append(f"Solidity vulnerability: {vtype} ({swc})")
        severity = candidate.get("severity", "")
        if severity:
            parts.append(f"Severity: {severity}")
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
            parts.append(f"Code: {code[:1000]}")
        return ". ".join(parts) if parts else str(candidate)


# =============================================================================
# CRAG EVALUATOR (Corrective Retrieval Augmented Generation)
# =============================================================================

class CRAGEvaluator:
    """
    Corrective RAG evaluator based on Yan et al. (arXiv:2401.15884).

    Adapted for voyage-rerank-2.5 scores (pre-calibrated [0, 1]):
    - CORRECT (score >= 0.7): Highly relevant, pass all evidence to LLM
    - AMBIGUOUS (0.3 <= score < 0.7): Partially relevant, pass filtered evidence
    - INCORRECT (score < 0.3): Irrelevant, discard and let LLM judge alone

    voyage-rerank-2.5 understands code natively, so the bi-encoder floor
    workaround (needed when ms-marco NL-only reranker disagreed with
    CodeRankEmbed on code similarity) is no longer necessary.
    """

    CORRECT_THRESHOLD = 0.7
    INCORRECT_THRESHOLD = 0.3

    def evaluate(self, candidates: List[Dict]) -> tuple:
        """
        Evaluate retrieval quality and determine action.

        Uses MAX relevance_score across all candidates (not just [0]).

        Decision logic:
        1. Max relevance_score >= 0.7 → CORRECT (high confidence)
        2. Max relevance_score >= 0.3 → AMBIGUOUS (partial relevance)
        3. Otherwise → INCORRECT (discard, LLM judges alone)

        Args:
            candidates: Reranked candidates (must have 'relevance_score'
                        field from VoyageReranker)

        Returns:
            (action, filtered_candidates):
                action: "CORRECT" | "AMBIGUOUS" | "INCORRECT"
                filtered_candidates: evidence to pass to LLM (may be empty)
        """
        if not candidates:
            return "INCORRECT", []

        max_relevance = max(c.get("relevance_score", 0) for c in candidates)

        if max_relevance >= self.CORRECT_THRESHOLD:
            return "CORRECT", candidates

        elif max_relevance >= self.INCORRECT_THRESHOLD:
            filtered = [
                c for c in candidates
                if c.get("relevance_score", 0) >= self.INCORRECT_THRESHOLD
            ]
            return "AMBIGUOUS", filtered

        else:
            return "INCORRECT", []


# =============================================================================
# SMART RAG SYSTEM v7
# =============================================================================

class SmartRAGSystem:
    """
    Smart RAG System v7 - Knowledge-level RAG for Smart Contract Vulnerability Detection

    Components:
    - voyage-code-3 (1024d) for code-specialized embedding
    - Qdrant (local mode) for vector similarity search with metadata filtering
    - voyage-rerank-2.5 for instruction-following reranking
    - CRAG evaluator for retrieval quality gating

    v7 Updates:
    - Replaced CodeRankEmbed with voyage-code-3 (code + NL, 300+ languages)
    - Replaced ms-marco-MiniLM with voyage-rerank-2.5 (code-aware, instruction-following)
    - Simplified scoring: relevance_score [0,1] from Voyage (no custom normalization)
    - Simplified CRAG: no bi-encoder floor workaround needed
    - 1024d vectors (up from 768d)
    """

    def __init__(self, persist_directory: str = QDRANT_PATH):
        print(f"[SmartRAG v7] Initializing...")

        self.persist_directory = persist_directory
        self.kb_version = "v8"

        # 1. voyage-code-3 embedding model
        print(f"[SmartRAG v7] Loading voyage-code-3 embedding model...")
        self.embedding = VoyageCodeEmbeddings()

        # 2. Qdrant vector database (local mode, no Docker)
        print(f"[SmartRAG v7] Connecting to Qdrant at {persist_directory}...")
        self.qdrant = QdrantClient(path=persist_directory)

        # Check collection
        collections = [c.name for c in self.qdrant.get_collections().collections]
        if COLLECTION_NAME in collections:
            info = self.qdrant.get_collection(COLLECTION_NAME)
            self.total_entries = info.points_count
            self.kb_version = "v8-voyage-code-3"
            print(f"[SmartRAG v7] KB Connected: {self.total_entries} entries")
        else:
            self.total_entries = 0
            print(f"[SmartRAG v7] WARNING: Collection '{COLLECTION_NAME}' not found. Run migrate_to_qdrant_v8.py first.")

        # 3. voyage-rerank-2.5 reranker
        print(f"[SmartRAG v7] Loading voyage-rerank-2.5 reranker...")
        self.reranker = VoyageReranker()

        # 4. CRAG evaluator
        self.crag = CRAGEvaluator()

        print(f"[SmartRAG v7] Ready!")

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
            "embedding": "voyage-code-3 (Voyage AI, 1024d)",
            "vector_db": "Qdrant (local mode)",
            "reranker": "voyage-rerank-2.5 (Voyage AI)",
            "crag": "CRAG evaluator (relevance_score gating)",
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

            # Retrieve with relaxed threshold — let voyage-rerank-2.5 reranker
            # decide relevance instead of hard-filtering at embedding stage.
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
            print(f"[SmartRAG v7] Embedding retrieved: {len(formatted)} results")

            return formatted

        except Exception as e:
            print(f"[SmartRAG v7] Search error: {e}")
            return []


if __name__ == "__main__":
    rag = SmartRAGSystem()
    stats = rag.get_stats()
    print(f"Stats: {stats}")
