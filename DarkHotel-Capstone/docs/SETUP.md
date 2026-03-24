# DarkHotel - Setup Guide

## Prerequisites

- Python 3.10+
- Node.js 18+
- Git

## Installation

### 1. Backend Setup

```bash
cd backend

# Tao virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Slither
pip install slither-analyzer

# Install solc-select
pip install solc-select
solc-select install 0.8.0 0.4.26 0.5.17 0.6.12 0.7.6
solc-select use 0.8.0
```

### 2. Configure API Key

```bash
cd backend
cp .env.example .env
```

Edit `.env`:

```env
GEMINI_API_KEY=your_gemini_api_key_here
MODEL_NAME=gemini-2.5-pro
QDRANT_DB_PATH=./qdrant_db_v7
```

Get API key: https://aistudio.google.com/apikey

> **Note:** Knowledge Base (`qdrant_db_v7/`) is included in repo with 458 enriched DAppSCAN entries. No need to re-ingest.

### 3. Frontend Setup

```bash
cd frontend
npm install
```

---

## Running the Application

### Terminal 1: Start Backend

```bash
cd backend
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

uvicorn main:app --reload --port 8000
```

Backend: http://127.0.0.1:8000

### Terminal 2: Start Frontend

```bash
cd frontend
npm run dev
```

Frontend: http://localhost:3000

---

## Testing

### Test Backend API

```bash
# Health check
curl http://127.0.0.1:8000/

# Upload contract
curl -X POST http://localhost:8000/analyze -F "file=@test.sol"
```

### Test with Postman

1. Method: `POST`
2. URL: `http://127.0.0.1:8000/analyze`
3. Body: `form-data`
   - Key: `file`
   - Value: [Select .sol file]

---

## Project Structure

```
DarkHotel-Capstone/
+-- backend/
|   +-- main.py                 # Pipeline orchestrator (6-step v6.0)
|   +-- ast_parser.py           # AST parser (tree-sitter + regex)
|   +-- smart_rag_system.py     # RAG v6 (CodeRankEmbed + Qdrant + Reranker + CRAG)
|   +-- llm_analyzer.py         # Gemini 2.5 Pro + CoT + anti-hallucination
|   +-- slither_smart_wrapper.py  # Slither + auto solc
|   +-- qdrant_db_v7/           # Vector DB (458 entries, enriched v7)
|   +-- requirements.txt
|   +-- .env                    # Config (not committed)
|
+-- frontend/
|   +-- app/page.tsx            # React dashboard
|   +-- package.json
|
+-- evaluation/
|   +-- run_smartbugs_eval.py   # SmartBugs benchmark
|   +-- run_top200_eval.py      # Top200 FP benchmark
|   +-- run_ablation_*.py       # Ablation studies
|
+-- docs/
    +-- SETUP.md                # This file
    +-- DEBUGGING.md            # Debug guide
    +-- WORKFLOW_V6.md          # System architecture (detailed)
```

---

## Troubleshooting

### Slither not found

```bash
pip install slither-analyzer
```

### solc version error

```bash
solc-select install 0.8.20
solc-select use 0.8.20
```

> System auto-installs solc from pragma if not available.

### Qdrant DB not found

Knowledge Base is in `backend/qdrant_db_v7/`. If missing:

```bash
cd backend
python migrate_to_qdrant_v7.py
```

### CORS blocking requests

Backend CORS is configured for all origins in development. Check backend is running.

---

## Sample Test File

Create `test.sol`:

```solidity
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        // REENTRANCY VULNERABILITY!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
```

Upload this file to test the system.

---

**Version:** 6.0
**Last Updated:** 2026-03-24
