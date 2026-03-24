# DarkHotel Frontend - Smart Contract Analyzer Dashboard

Frontend cho he thong phan tich lo hong Smart Contract, xay dung voi **Next.js + TypeScript + Tailwind CSS**.

**Version:** 5.1.0

---

## Tong Quan

Dashboard web cho phep:

1. Upload Solidity smart contract (.sol)
2. Theo doi tien trinh phan tich qua 6 pipeline steps
3. Hien thi ket qua co cau truc: Verdict, Primary/Secondary vulnerabilities
4. Xem chi tiet Slither, RAG, AI Reasoning (collapsible sections)

---

## Cong Nghe Su Dung

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js | 16.x (App Router) |
| Language | TypeScript | 5.x |
| Styling | Tailwind CSS | 4.x |
| Icons | Lucide React | Latest |
| Markdown | react-markdown | 10.x |
| React | React | 19.x |

---

## Cau Truc Thu Muc

```
frontend/
+-- app/
|   +-- page.tsx           # Main dashboard (upload + structured results)
|   +-- layout.tsx         # Root layout
|   +-- globals.css        # Global styles + Tailwind
+-- public/                # Static assets
+-- package.json           # Dependencies
+-- tsconfig.json          # TypeScript config
```

---

## Cai Dat

### Yeu cau

- Node.js 18+
- npm

### Install

```bash
cd frontend
npm install
```

---

## Chay Ung Dung

```bash
npm run dev
```

Truy cap: http://localhost:3000

**Luu y:** Backend phai dang chay tai `http://127.0.0.1:8000`

---

## Giao Dien

### 1. Upload Area

- Keo tha file `.sol` hoac click de chon
- Validation: chi chap nhan file `.sol`
- Hien thi ten file da chon

### 2. Pipeline Steps Tracker

Khi dang phan tich, hien thi tien trinh 6 buoc:

```
[1] Upload & Parse Contract      ---- done
[2] AST Function Extraction      ---- done
[3] Slither + RAG (parallel)     ---- running
[4] Weighted Ranking + Gate      ---- pending
[5] LLM Deep Analysis            ---- pending
[6] Generate Report              ---- pending
```

### 3. Verdict Banner

- **SAFE** (xanh la): Contract an toan
- **VULNERABLE** (do): Phat hien lo hong

### 4. Primary Vulnerability Card

- Severity badge (Critical/High/Medium/Low)
- SWC ID
- Vi tri (function, line number)
- Mo ta chi tiet
- Exploit scenario
- Recommendation

### 5. Secondary Warnings

- Danh sach cac lo hong phu
- Severity badge cho tung warning

### 6. Collapsible Sections

- **Slither Analysis** (cam): Static analysis warnings, color-coded theo severity
- **RAG Knowledge Base** (tim): Similar cases, confidence scores
- **AI Reasoning** (cyan): Chain-of-Thought tu LLM

### 7. Contract Info Sidebar

- Solidity version, so luong contracts, functions
- Risky functions, modifiers

---

## API Integration

```typescript
const API_URL = "http://127.0.0.1:8000";

// Upload & Analyze
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch(`${API_URL}/analyze`, {
  method: "POST",
  body: formData,
});

const result = await response.json();
// result.ai_analysis_structured: {verdict, primary_vulnerability, secondary_warnings, reasoning}
// result.rag_findings: {found, vuln_type, similar_cases, detected_vulnerabilities}
// result.slither_analysis: {warnings, hints_used, total_warnings}
```

---

## Troubleshooting

### Loi: `Failed to fetch` khi upload

Backend chua chay. Kiem tra:

```bash
curl http://127.0.0.1:8000/
```

### Loi: Port 3000 already in use

```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

### Loi: Module not found

```bash
npm install
```

---

## Build Production

```bash
npm run build
npm start
```

---

**Version:** 5.1.0
**Last Updated:** 2026-03-12
**Backend:** FastAPI (http://127.0.0.1:8000)
