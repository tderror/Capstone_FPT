# DarkHotel - Smart Contract Vulnerability Analyzer

AI-powered Solidity vulnerability detection using a **6-Step Sequential Pipeline**: AST Chunking (tree-sitter) + Slither + RAG (CodeRankEmbed + Qdrant) + Cross-Encoder Reranking + CRAG Gate + LLM Chain-of-Thought.

![Version](https://img.shields.io/badge/Version-6.0-blue)
![Backend](https://img.shields.io/badge/Backend-FastAPI-green)
![Frontend](https://img.shields.io/badge/Frontend-Next.js%2016-black)
![AI](https://img.shields.io/badge/AI-Gemini%202.5%20Pro-purple)
![RAG](https://img.shields.io/badge/RAG-DAppSCAN%20458%20cases-orange)

---

## Overview

DarkHotel phan tich smart contract Solidity qua 6 buoc:

```
Upload .sol  -->  [1] AST Chunking  -->  [2+3] Slither + RAG (parallel)
                                                      |
                  [6] Report  <--  [5] LLM CoT  <--  [4] Weighted Ranking + RAG Gate
```

| Step | Component | Technology | Purpose |
|------|-----------|-----------|---------|
| 1 | AST Chunking | tree-sitter + Regex fallback | Tach function, xac dinh risky functions |
| 2 | Slither | Static Analyzer | Phat hien pattern, tao hints cho RAG |
| 3 | RAG Search | Qdrant + CodeRankEmbed (768d) | Tim vuln tuong tu trong 458 case DAppSCAN |
| 4 | Cross-Encoder Reranking + CRAG Gate | ms-marco-MiniLM + Rule-based CRAG | Rerank + quality gate (Correct/Ambiguous/Incorrect) |
| 5 | LLM CoT | Gemini 2.5 Pro | Chain-of-Thought reasoning + 14 anti-hallucination rules |
| 6 | Report | JSON structured | Verdict + vulnerabilities + evidence |

### 3 Loai Vulnerability Duoc Kiem Tra

| Type | SWC ID | Severity | Description |
|------|--------|----------|-------------|
| Reentrancy | SWC-107 | Critical/High | External call truoc state update (CEI violation) |
| Integer Overflow/Underflow | SWC-101 | High | Arithmetic overflow/underflow (pre-0.8, khong co SafeMath) |
| Unchecked Return Value | SWC-104 | Medium/High | .send()/.call() khong kiem tra return value |

---

## Quick Start

### Yeu Cau He Thong

- **Python** 3.10+
- **Node.js** 18+
- **Git**
- **Gemini API Key** (lay tai: https://aistudio.google.com/apikey)

### 1. Clone Repository

```bash
git clone https://github.com/quackfpt/DarkHotel-Capstone.git
cd DarkHotel-Capstone
```

### 2. Setup Backend

```bash
cd backend

# Tao virtual environment
python -m venv venv

# Kich hoat (Windows)
venv\Scripts\activate

# Kich hoat (Linux/Mac)
# source venv/bin/activate

# Cai dat dependencies
pip install -r requirements.txt

# Cai dat Slither
pip install slither-analyzer

# Cai dat solc-select (quan ly Solidity compiler versions)
pip install solc-select
solc-select install 0.8.0 0.4.26 0.5.17 0.6.12 0.7.6
solc-select use 0.8.0
```

### 3. Cau Hinh API Key

```bash
# Tao file .env tu template
cp .env.example .env
```

Mo file `backend/.env` va them API key:

```env
GEMINI_API_KEY=your_gemini_api_key_here
MODEL_NAME=gemini-2.5-pro
QDRANT_DB_PATH=./qdrant_db_v7
```

> **Luu y:** Knowledge Base (`qdrant_db_v7/`) da duoc bao gom san trong repo voi 458 DAppSCAN entries (enriched v7). Khong can chay ingest lai.

### 4. Setup Frontend

```bash
cd ../frontend
npm install
```

### 5. Chay Ung Dung

**Terminal 1 - Backend:**
```bash
cd backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

### 6. Truy Cap

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

---

## Cach Su Dung

1. Mo http://localhost:3000
2. Keo tha file `.sol` vao khu vuc upload (hoac click de chon file)
3. Nhan **Analyze Contract**
4. Doi 30-45 giay de he thong phan tich qua 6 buoc
5. Xem ket qua:
   - **Verdict Banner**: SAFE (xanh) hoac VULNERABLE (do)
   - **Primary Vulnerability**: Loi chinh voi severity, SWC ID, exploit scenario, recommendation
   - **Secondary Warnings**: Cac loi phu
   - **Slither Analysis**: Ket qua static analysis
   - **RAG Knowledge Base**: Similar cases tu DAppSCAN
   - **AI Reasoning**: Chain-of-Thought tu LLM

---

## Project Structure

```
DarkHotel-Capstone/
|
+-- backend/
|   +-- main.py                         # FastAPI server (6-step pipeline v6.0)
|   +-- ast_parser.py                   # AST chunking - tree-sitter + regex (Step 1)
|   +-- slither_smart_wrapper.py        # Slither integration + auto solc (Step 2)
|   +-- smart_rag_system.py             # RAG v6 - CodeRankEmbed + Qdrant + Reranker + CRAG (Step 3-4)
|   +-- llm_analyzer.py                 # Gemini 2.5 Pro + CoT + 14 anti-hallucination rules (Step 5)
|   |
|   +-- qdrant_db_v7/                   # Vector DB (458 DAppSCAN entries, enriched v7)
|   +-- darkhotel_knowledge_base_v7.json  # Knowledge base source (JSON)
|   +-- .env.example                    # Environment template
|   +-- requirements.txt                # Python dependencies
|
+-- frontend/
|   +-- app/
|   |   +-- page.tsx                    # Main dashboard (structured results UI)
|   |   +-- layout.tsx                  # Root layout
|   |   +-- globals.css                 # Global styles
|   +-- package.json
|
+-- evaluation/
|   +-- run_smartbugs_eval.py           # SmartBugs-Curated evaluation (98 vulnerable)
|   +-- run_top200_eval.py              # GPTScan Top200 evaluation (225 safe)
|   +-- run_top10_reentrancy_eval.py    # Top10 reentrancy evaluation
|   +-- run_ablation_llm_only_*.py      # Ablation study (LLM-only, no RAG)
|   +-- review2_report.html             # Review 2 report (HTML)
|   |
|   +-- external_datasets/
|   |   +-- SmartBugs-Curated/          # 98 vulnerable contracts (SWC-107/101/104)
|   |   +-- safe_contracts/             # 23 verified safe contracts
|   |   +-- top_10_reentrancy/          # 10 reentrancy test contracts
|
+-- README.md                           # This file
```

---

## Evaluation Results (v6.0)

> *Chua co ket qua. Can chay lai evaluation sau khi test.*

---

## Tech Stack

### Backend

| Component | Technology |
|-----------|-----------|
| Web Framework | FastAPI 0.128+ |
| Static Analyzer | Slither |
| Vector Database | Qdrant (local mode) |
| Embeddings | CodeRankEmbed (nomic-ai, 768d, ICLR 2025) |
| Reranker | ms-marco-MiniLM-L-6-v2 (cross-encoder) |
| RAG Quality Gate | CRAG Evaluator (rule-based) |
| LLM | Gemini 2.5 Pro |
| Python | 3.10+ |

### Frontend

| Component | Technology |
|-----------|-----------|
| Framework | Next.js 16 (App Router) |
| Language | TypeScript 5.x |
| Styling | Tailwind CSS 4.x |
| Icons | Lucide React |

---

## API

### Health Check

```bash
curl http://localhost:8000/
```

### Analyze Contract

```bash
curl -X POST http://localhost:8000/analyze -F "file=@contract.sol"
```

Response tra ve JSON voi:
- `ai_analysis_structured`: verdict, primary vulnerability, secondary warnings, reasoning
- `rag_findings`: similar cases, detected vulnerabilities, confidence scores
- `slither_analysis`: static analysis warnings
- `function_analysis`: risky functions tu AST

---

## Troubleshooting

### Backend khong khoi dong

```bash
# Kiem tra Python version
python --version  # Can 3.10+

# Cai lai dependencies
pip install -r requirements.txt
```

### Slither loi version solc

```bash
# He thong tu dong cai solc version tu pragma
# Neu van loi, cai thu cong:
solc-select install 0.8.20
solc-select use 0.8.20
```

### Frontend loi ket noi

```bash
# Kiem tra backend dang chay
curl http://localhost:8000/
```

### Database not found

```bash
cd backend
# Rebuild Qdrant v7 tu knowledge base JSON
python migrate_to_qdrant_v7.py
```

---

## License

MIT License

---

**Version:** 6.0
**Last Updated:** 2026-03-24
**Knowledge Base:** 458 DAppSCAN entries (enriched v7, 29 security teams, 608 audits)
**Embedding:** CodeRankEmbed (nomic-ai, 768d, ICLR 2025)
**Reranker:** ms-marco-MiniLM-L-6-v2 (cross-encoder)
**Vector DB:** Qdrant (local mode)
**Detection:** Reentrancy (SWC-107), Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)

**Made by DarkHotel Team**
