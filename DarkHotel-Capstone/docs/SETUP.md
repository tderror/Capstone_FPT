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

### 2. Configure API Keys

```bash
cd backend
cp .env.example .env
```

Edit `.env`:

```env
GOOGLE_CLOUD_PROJECT=your_project_id_here
GOOGLE_CLOUD_LOCATION=us-central1
MODEL_NAME=gemini-2.5-pro
VOYAGE_API_KEY=your_voyage_api_key_here
QDRANT_DB_PATH=./qdrant_db_v8
```

Get API keys:
- **Gemini**: https://aistudio.google.com/apikey
- **Voyage AI**: https://dash.voyageai.com/ (dang ky free tier)

> **Note:** Can chay `python migrate_to_qdrant_v8.py` lan dau de build Knowledge Base (`qdrant_db_v8/`) voi 407 DAppSCAN entries su dung voyage-code-3 embeddings.

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
|   +-- main.py                 # Pipeline orchestrator (6-step v7.0)
|   +-- ast_parser.py           # AST parser (tree-sitter + regex)
|   +-- smart_rag_system.py     # RAG v7 (voyage-code-3 + Qdrant + voyage-rerank-2.5 + CRAG)
|   +-- llm_analyzer.py         # Gemini 2.5 Pro + CoT + anti-hallucination
|   +-- slither_smart_wrapper.py  # Slither + auto solc
|   +-- migrate_to_qdrant_v8.py # Build Qdrant DB from KB JSON
|   +-- qdrant_db_v8/           # Vector DB (407 entries, voyage-code-3 1024d)
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

Knowledge Base is in `backend/qdrant_db_v8/`. If missing:

```bash
cd backend
python migrate_to_qdrant_v8.py
```

### Voyage API key errors

```bash
# Kiem tra VOYAGE_API_KEY trong .env
# Lay key tai: https://dash.voyageai.com/
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

**Version:** 7.0
**Last Updated:** 2026-04-01
