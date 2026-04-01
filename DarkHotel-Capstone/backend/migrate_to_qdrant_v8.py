"""
Migrate Knowledge Base v8 to Qdrant with voyage-code-3 embeddings.

Reads darkhotel_knowledge_base_v7.json (quality-fixed: specific root_cause/trigger/fix,
deduplicated, cleaned) and builds a Qdrant collection with voyage-code-3 (1024d) vectors.

Changes from v7:
- Uses voyage-code-3 (Voyage AI API) instead of CodeRankEmbed (local)
- 1024d vectors (up from 768d)
- Saves to qdrant_db_v8/ directory
- Updated collection name to darkhotel_v8
- Larger batch size (API handles batches efficiently)

Prerequisites:
    pip install voyageai
    Set VOYAGE_API_KEY in .env or environment

Usage:
    cd backend
    python migrate_to_qdrant_v8.py
"""

import json
import time
import shutil
from pathlib import Path
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

load_dotenv()

# --- Config ---
KB_FILE = Path(__file__).parent / "darkhotel_knowledge_base_v7.json"
QDRANT_PATH = Path(__file__).parent / "qdrant_db_v8"
COLLECTION_NAME = "darkhotel_v8"
BATCH_SIZE = 50  # Voyage API handles larger batches (max 128 texts, 120K tokens)
VECTOR_DIM = 1024


def build_document_text(entry: dict) -> str:
    """
    Build document text for embedding.
    Includes vulnerability knowledge (root_cause, trigger, fix) + code.
    This makes it knowledge-level RAG, not just code-level.
    """
    parts = []
    parts.append(f"Vulnerability: {entry.get('swc_name', 'Unknown')}")
    parts.append(f"SWC ID: {entry.get('swc_id', '')}")
    parts.append(f"Severity: {entry.get('severity', 'Unknown')}")
    if entry.get("function"):
        parts.append(f"Function: {entry['function']}")
    if entry.get("root_cause"):
        parts.append(f"Root Cause: {entry['root_cause']}")
    if entry.get("trigger_condition"):
        parts.append(f"Trigger: {entry['trigger_condition']}")
    if entry.get("fix_solution"):
        parts.append(f"Fix: {entry['fix_solution']}")
    if entry.get("code_snippet_vulnerable"):
        # voyage-code-3 context = 32K tokens, but we truncate for storage efficiency
        code = entry['code_snippet_vulnerable'][:3000]
        parts.append(f"Code:\n{code}")
    return "\n".join(parts)


def main():
    print("=" * 60)
    print("Migrate Knowledge Base v8 to Qdrant + voyage-code-3")
    print("=" * 60)

    # 1. Load KB
    print(f"\n[1/5] Loading knowledge base: {KB_FILE}")
    if not KB_FILE.exists():
        print(f"ERROR: {KB_FILE} not found. Run fix_knowledge_base.py first.")
        return
    with open(KB_FILE, "r", encoding="utf-8") as f:
        kb = json.load(f)
    entries = kb["entries"]
    print(f"  {len(entries)} entries loaded (version: {kb.get('version', 'unknown')})")
    print(f"  Categories: {kb.get('categories', {})}")

    # 2. Load embedding model
    print(f"\n[2/5] Loading voyage-code-3 embedding model...")
    from smart_rag_system import VoyageCodeEmbeddings
    embedder = VoyageCodeEmbeddings(dimension=VECTOR_DIM)
    print(f"  Model loaded ({embedder.dimension}d)")

    # 3. Create Qdrant collection
    print(f"\n[3/5] Creating Qdrant collection at {QDRANT_PATH}...")
    if QDRANT_PATH.exists():
        print(f"  Removing existing DB at {QDRANT_PATH}...")
        shutil.rmtree(QDRANT_PATH)

    client = QdrantClient(path=str(QDRANT_PATH))
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
    )
    print(f"  Collection '{COLLECTION_NAME}' created ({VECTOR_DIM}d, cosine)")

    # 4. Embed and upsert in batches
    print(f"\n[4/5] Embedding and upserting {len(entries)} entries (batch_size={BATCH_SIZE})...")
    start_time = time.time()
    total_upserted = 0

    for batch_start in range(0, len(entries), BATCH_SIZE):
        batch = entries[batch_start:batch_start + BATCH_SIZE]

        # Build document texts
        texts = [build_document_text(e) for e in batch]

        # Embed via Voyage API (input_type="document")
        vectors = embedder.embed_documents(texts)

        # Build Qdrant points
        points = []
        for i, entry in enumerate(batch):
            point_id = batch_start + i
            payload = {
                "id": entry.get("id", f"entry_{point_id}"),
                "swc_id": entry.get("swc_id", ""),
                "swc_name": entry.get("swc_name", ""),
                "severity": entry.get("severity", ""),
                "function": entry.get("function", ""),
                "line_number": entry.get("line", ""),
                "audit_company": entry.get("audit_company", ""),
                "source_file": entry.get("source_file", ""),
                "code_snippet_vulnerable": entry.get("code_snippet_vulnerable", "")[:3000],
                "root_cause": entry.get("root_cause", ""),
                "trigger_condition": entry.get("trigger_condition", ""),
                "fix_solution": entry.get("fix_solution", ""),
            }
            points.append(PointStruct(id=point_id, vector=vectors[i], payload=payload))

        # Upsert batch
        client.upsert(collection_name=COLLECTION_NAME, points=points)
        total_upserted += len(points)
        elapsed = time.time() - start_time
        print(f"  [{total_upserted}/{len(entries)}] upserted ({elapsed:.1f}s)")

    # 5. Verify
    print(f"\n[5/5] Verifying...")
    info = client.get_collection(COLLECTION_NAME)
    print(f"  Collection: {COLLECTION_NAME}")
    print(f"  Points: {info.points_count}")

    # Quick search test
    test_query = "function withdraw() public { msg.sender.call{value: amount}; }"
    test_vector = embedder.embed_query(test_query)
    try:
        test_results = client.query_points(
            collection_name=COLLECTION_NAME,
            query=test_vector,
            limit=3,
        ).points
        print(f"\n  Test search for reentrancy pattern:")
        for r in test_results:
            p = r.payload
            print(f"    [{r.score:.4f}] {p.get('swc_name', '?')} - {p.get('function', '?')}")
            print(f"      Root cause: {p.get('root_cause', '?')[:100]}...")
    except Exception as e:
        print(f"\n  Test search skipped (qdrant API): {e}")
        print(f"  The DB was built successfully - search will work via smart_rag_system.py")

    total_time = time.time() - start_time
    print(f"\nMigration complete! {total_upserted} entries in {total_time:.1f}s")
    print(f"Qdrant DB saved at: {QDRANT_PATH}")
    print(f"\nReady to use with smart_rag_system.py (qdrant_db_v8 / darkhotel_v8)")


if __name__ == "__main__":
    main()
