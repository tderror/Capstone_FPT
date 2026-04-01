# Debugging Guide - DarkHotel v7.0

## Pipeline Logging

He thong log chi tiet qua terminal backend (uvicorn). Khi upload file, xem logs theo thu tu:

```
[PIPELINE v7.0] 6-Step Analysis
[INPUT] File: contract.sol, Size: 1523 bytes
[STEP 1/6] AST Chunking - extracting functions...
   -> Solidity: 0.8.0
   -> Contracts: 1, Functions: 3
   -> Risky functions: 1
   -> Parse method: tree-sitter
[STEP 2+3/6] Slither + RAG Search (parallel)...
   -> Slither: 2 warnings, hints: ['reentrancy-eth']
   -> RAG: searched 1 risky functions
   -> Raw: 10, Unique: 8
[STEP 4/6] Voyage reranking + CRAG gate...
   -> 8 candidates -> 5 reranked results
   [1] Reentrancy (bi=0.7234, relevance=0.8912)
   -> CRAG gate: CORRECT (top relevance=0.8912)
   -> CRAG: CORRECT -> sending 5 evidence to LLM
[STEP 5/6] LLM Chain-of-Thought reasoning...
   -> LLM completed (1234 tokens)
[STEP 6/6] Generating report...
[DONE] Analysis complete!
```

---

## Debug Checklist

Truoc khi bao loi, check:

- [ ] Backend da start: `uvicorn main:app --reload --port 8000`
- [ ] Frontend da start: `npm run dev`
- [ ] API keys dung trong `backend/.env` (GOOGLE_CLOUD_PROJECT, VOYAGE_API_KEY)
- [ ] Qdrant DB co tai `backend/qdrant_db_v8/`
- [ ] File upload la `.sol` va khong rong

---

## Common Issues

### 1. Backend khong khoi dong

```bash
# Check error message trong terminal
# Thuong gap: VOYAGE_API_KEY not found hoac GOOGLE_CLOUD_PROJECT not set
# Fix: tao file backend/.env tu .env.example va dien API keys
cp .env.example .env
```

### 2. Slither loi

```bash
# Slither tu dong fallback sang regex neu loi
# Neu can fix: install dung solc version
solc-select install 0.8.20
solc-select use 0.8.20
```

### 3. RAG khong tim thay ket qua

- Kiem tra `qdrant_db_v8/` co ton tai
- Neu mat, rebuild: `cd backend && python migrate_to_qdrant_v8.py`
- Kiem tra VOYAGE_API_KEY con valid (can cho embedding + reranking)

### 4. LLM timeout hoac error

- Kiem tra internet connection
- Kiem tra API key con valid
- Kiem tra quota Gemini API: https://aistudio.google.com/apikey
- Thu lai sau 1 phut (rate limit)

### 5. Frontend khong ket noi backend

```bash
# Kiem tra backend dang chay
curl http://127.0.0.1:8000/

# Kiem tra CORS trong browser console (F12)
# Backend da config allow_origins=["*"]
```

### 6. CRAG Gate luon INCORRECT

```
-> CRAG gate: INCORRECT (top relevance=0.1234)
-> CRAG: INCORRECT -> LLM judges alone (no RAG evidence)
```

Day la hanh vi binh thuong khi code khong giong voi cac case trong KB.
LLM se tu phan doan (= LLM-only mode). Khong phai loi.

### 7. Voyage API errors

```
# Kiem tra VOYAGE_API_KEY trong .env
# Kiem tra quota tai: https://dash.voyageai.com/

# Test connection:
python -c "
import voyageai, os
from dotenv import load_dotenv
load_dotenv()
vo = voyageai.Client(api_key=os.getenv('VOYAGE_API_KEY'))
r = vo.embed(texts=['test'], model='voyage-code-3', input_type='query')
print(f'OK: {len(r.embeddings[0])}d vector')
"
```

---

## Test tung Component

### Test AST Parser

```bash
cd backend
python -c "
from ast_parser import SolidityASTParser
parser = SolidityASTParser()
code = open('path/to/contract.sol').read()
result = parser.parse(code)
print(parser.get_summary(result))
"
```

### Test RAG Search

```bash
cd backend
python -c "
from smart_rag_system import SmartRAGSystem
rag = SmartRAGSystem(persist_directory='./qdrant_db_v8')
stats = rag.get_stats()
print(stats)
"
```

### Test Slither

```bash
cd backend
python -c "
from slither_smart_wrapper import SmartSlitherWrapper
slither = SmartSlitherWrapper()
code = open('path/to/contract.sol').read()
warnings = slither.get_warnings_for_ai(code)
print(f'Warnings: {len(warnings)}')
"
```

---

**Version:** 7.0
**Last Updated:** 2026-04-01
