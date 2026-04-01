# DarkHotel Backend - Smart Contract Analyzer API v7.0

API phan tich lo hong smart contract Solidity su dung **6-Step Sequential Pipeline**: AST (tree-sitter) + Slither + RAG (voyage-code-3 + Qdrant) + Voyage Reranking + CRAG Gate + LLM CoT.

---

## Pipeline v7.0

```
Upload .sol
    |
    v
[1] AST Chunking ---- tree-sitter (primary) + regex fallback
    |
    v  (PARALLEL)
[2] Slither ---------- Static analysis, extract hints
[3] RAG Search ------- Per-function search trong 407 DAppSCAN cases (voyage-code-3 + Qdrant)
    |
    v
[4] Voyage Reranking + CRAG Gate
    |  voyage-rerank-2.5 (instruction-following, code-aware)
    |  CRAG: CORRECT (>=0.7) -> full evidence
    |        AMBIGUOUS (0.3-0.7) -> filtered evidence
    |        INCORRECT (<0.3) -> no evidence (LLM-only mode)
    v
[5] LLM CoT --------- Chain-of-Thought + 14 anti-hallucination rules
    |
    v
[6] JSON Report ------ Verdict + vulnerabilities + evidence
```

### 3 Loai Vulnerability

| Type | SWC ID | Detection |
|------|--------|-----------|
| Reentrancy | SWC-107 | AST (external_call + state_change + no reentrancy_guard) |
| Integer Overflow | SWC-101 | Operator-based (+=, -=, ++, --) + version check (pre-0.8) |
| Unchecked Return Value | SWC-104 | AST (has_external_call) + unchecked pattern |

### Key Features (v7.0)

- **voyage-code-3**: Voyage AI, 1024d, code-specialized embedding (300+ languages)
- **Qdrant**: Local vector database (no Docker required)
- **voyage-rerank-2.5**: Instruction-following reranker (code-aware, relevance_score [0,1])
- **CRAG Gate**: Rule-based Corrective RAG evaluator (Correct/Ambiguous/Incorrect)
- **14 anti-hallucination rules**: Strict SWC type filtering in LLM prompt
- **Parallel execution**: Slither + RAG chay dong thoi (asyncio.gather)
- **ERC20 filter**: Phan biet .transfer(addr) (ETH) va .transfer(addr, uint) (ERC20)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web Framework | FastAPI 0.128+ |
| Static Analyzer | Slither (auto solc install) |
| Vector Database | Qdrant (local mode) |
| Embeddings | voyage-code-3 (Voyage AI, 1024d) |
| Reranker | voyage-rerank-2.5 (Voyage AI, instruction-following) |
| RAG Quality Gate | CRAG Evaluator (rule-based) |
| LLM | Gemini 2.5 Pro |
| Python | 3.10+ |

---

## Cau Truc

```
backend/
+-- main.py                     # FastAPI server (6-step pipeline v7.0)
+-- ast_parser.py               # AST parser (tree-sitter + regex fallback)
+-- slither_smart_wrapper.py    # Slither + auto solc version install
+-- smart_rag_system.py         # RAG v7 (voyage-code-3 + Qdrant + voyage-rerank-2.5 + CRAG)
+-- llm_analyzer.py             # LLM CoT + 14 anti-hallucination rules
|
+-- qdrant_db_v8/               # Vector DB (Qdrant, 407 DAppSCAN entries, voyage-code-3 1024d)
+-- darkhotel_knowledge_base_v7.json  # Knowledge base source
+-- migrate_to_qdrant_v8.py     # Script rebuild Qdrant DB tu JSON (voyage-code-3)
+-- migrate_to_qdrant_v7.py     # Legacy migration script (CodeRankEmbed, 768d)
+-- .env                        # Environment config (khong commit)
+-- .env.example                # Config template
+-- requirements.txt            # Python dependencies
```

---

## Cai Dat

### 1. Tao virtual environment

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 2. Cai dependencies

```bash
pip install -r requirements.txt
pip install slither-analyzer

# Cai solc-select (quan ly Solidity compiler)
pip install solc-select
solc-select install 0.8.0 0.4.26 0.5.17 0.6.12 0.7.6
solc-select use 0.8.0
```

> **Luu y:** He thong tu dong cai solc version tu pragma neu chua co.

### 3. Cau hinh API key

```bash
cp .env.example .env
```

Sua file `.env`:

```env
GOOGLE_CLOUD_PROJECT=your_project_id_here
GOOGLE_CLOUD_LOCATION=us-central1
MODEL_NAME=gemini-2.5-pro
VOYAGE_API_KEY=your_voyage_api_key_here
QDRANT_DB_PATH=./qdrant_db_v8
```

Lay Voyage API key tai: https://dash.voyageai.com/

### 4. Build Knowledge Base (lan dau)

```bash
cd backend
python migrate_to_qdrant_v8.py
```

Script se embed 407 entries bang voyage-code-3 va luu vao `qdrant_db_v8/`.

---

## Chay Server

```bash
# Development
uvicorn main:app --reload --port 8000

# Production
uvicorn main:app --host 0.0.0.0 --port 8000
```

Server: http://localhost:8000

---

## API Endpoints

### Health Check

```bash
GET /
```

### Analyze Contract

```bash
POST /analyze
Content-Type: multipart/form-data

curl -X POST http://localhost:8000/analyze -F "file=@contract.sol"
```

Response:

```json
{
  "success": true,
  "filename": "contract.sol",
  "pipeline_version": "7.0-6step",
  "ai_analysis_structured": {
    "verdict": "VULNERABLE",
    "confidence": "HIGH",
    "primary_vulnerability": {
      "type": "Reentrancy",
      "swc_id": "SWC-107",
      "severity": "Critical",
      "location": "withdraw() at line 15"
    }
  },
  "rag_findings": {
    "found": true,
    "vuln_type": "Reentrancy (SWC-107)",
    "crag_action": "CORRECT",
    "similar_cases": [],
    "total_candidates": 15,
    "top_k_ranked": 5,
    "version": "v7.0-qdrant-voyage-code-3"
  },
  "slither_analysis": {
    "warnings": ["[High] reentrancy-eth: ..."],
    "hints_used": ["reentrancy-eth"],
    "total_warnings": 1
  },
  "function_analysis": {
    "total_functions": 5,
    "risky_functions": 2
  }
}
```

---

## Troubleshooting

### Slither loi solc version

```bash
solc-select install 0.8.20
solc-select use 0.8.20
```

### Database not found

Rebuild Knowledge Base:

```bash
cd backend
python migrate_to_qdrant_v8.py
```

### Voyage API key error

Kiem tra `VOYAGE_API_KEY` trong file `.env`. Lay key tai https://dash.voyageai.com/

---

**Version**: 7.0
**Last Updated**: 2026-04-01
**Knowledge Base**: 407 DAppSCAN entries (enriched v7, 29 security teams, 608 audits)
**Embedding**: voyage-code-3 (Voyage AI, 1024d)
**Reranker**: voyage-rerank-2.5 (Voyage AI, instruction-following)
**Vector DB**: Qdrant (local mode)
**Detection**: Reentrancy (SWC-107), Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)
