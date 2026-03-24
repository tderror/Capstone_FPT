# DarkHotel Evaluation Framework v6.0

Evaluation framework cho he thong phat hien lo hong Smart Contract DarkHotel v6.0.

---

## Ket Qua Evaluation v6.0

> *Chua co ket qua. Can chay lai evaluation sau khi test.*

---

## Cau Truc Thu Muc

```
evaluation/
+-- run_smartbugs_eval.py           # Eval SmartBugs-Curated (98 vulnerable contracts)
+-- run_safe_contracts_eval.py      # Eval Safe Contracts (23 verified safe)
+-- run_top200_eval.py              # Eval GPTScan Top200 (225 production contracts)
+-- run_top10_reentrancy_eval.py    # Eval Top10 reentrancy
+-- run_ablation_llm_only_smartbugs.py  # Ablation: LLM-only on SmartBugs
+-- run_ablation_llm_only_top200.py     # Ablation: LLM-only on Top200
|
+-- smartbugs_evaluation_results.json       # Ket qua SmartBugs v6.0
+-- safe_contracts_evaluation_results.json  # Ket qua Safe Contracts
+-- top200_evaluation_results.json          # Ket qua Top200 v6.0
+-- top10_reentrancy_results.json           # Ket qua Top10 reentrancy
+-- ablation_llm_only_smartbugs_results.json  # Ket qua ablation SmartBugs
+-- ablation_llm_only_top200_results.json     # Ket qua ablation Top200
|
+-- evaluation_summary.txt          # Tong hop ket qua
+-- review2_report.html             # Bao cao Review 2 (HTML)
|
+-- smartbugs_ground_truth.json     # Ground truth SmartBugs mapping
+-- safe_contracts_ground_truth.json  # Ground truth Safe Contracts
|
+-- external_datasets/
    +-- SmartBugs-Curated/          # 98 vulnerable contracts (SWC-107/101/104)
    +-- safe_contracts/             # 23 verified safe contracts
    +-- top_10_reentrancy/          # 10 reentrancy test contracts
    +-- GPTScan-Top200/             # 225 production contracts (download rieng)
    +-- DAppSCAN/                   # DAppSCAN dataset (download rieng)
```

---

## Huong Dan Chay Evaluation

### Yeu cau chung

Backend phai dang chay:

```bash
cd backend
venv\Scripts\activate
uvicorn main:app --port 8000
```

### 1. SmartBugs-Curated (98 vulnerable contracts)

Dataset da co san trong repo (`external_datasets/SmartBugs-Curated/`).

```bash
cd evaluation
python run_smartbugs_eval.py
```

- **Thoi gian**: ~70 phut (avg 42.8s/contract)
- **Output**: `smartbugs_evaluation_results.json`
- **Resume neu bi gian doan**: `python run_smartbugs_eval.py --resume`

### 2. Safe Contracts (23 verified safe contracts)

Dataset da co san trong repo (`external_datasets/safe_contracts/`).

```bash
cd evaluation
python run_safe_contracts_eval.py
```

- **Thoi gian**: ~15 phut
- **Output**: `safe_contracts_evaluation_results.json`

### 3. GPTScan Top200 (225 production contracts)

**Download dataset truoc** (khong co san trong repo):

```bash
cd evaluation/external_datasets
git clone https://github.com/nickyoung92/GPTScan-Top200.git
```

Chay evaluation:

```bash
cd evaluation
python run_top200_eval.py
```

- **Thoi gian**: ~2 gio (225 contracts, avg 33s/contract)
- **Output**: `top200_evaluation_results.json`
- **Resume neu bi gian doan**: `python run_top200_eval.py --resume`

### 4. Top10 Reentrancy

Dataset da co san (`external_datasets/top_10_reentrancy/`).

```bash
cd evaluation
python run_top10_reentrancy_eval.py
```

- **Thoi gian**: ~7 phut
- **Output**: `top10_reentrancy_results.json`

### 5. Ablation Study (LLM-only)

```bash
cd evaluation

# SmartBugs ablation
python run_ablation_llm_only_smartbugs.py

# Top200 ablation
python run_ablation_llm_only_top200.py
```

- **Output**: `ablation_llm_only_smartbugs_results.json`, `ablation_llm_only_top200_results.json`

---

## Metrics Definition

| Metric | Formula | Description |
|--------|---------|-------------|
| **Precision** | TP / (TP + FP) | Khi bao "co loi", dung bao nhieu %? |
| **Recall** | TP / (TP + FN) | Ty le phat hien dung |
| **F1-Score** | 2 * P * R / (P + R) | Trung binh dieu hoa Precision & Recall |
| **Specificity** | TN / (TN + FP) | Ty le nhan dien SAFE dung |
| **FPR** | FP / (FP + TN) | Ty le bao dong gia (thap = tot) |

---

## References

| Paper | Source | Description |
|-------|--------|-------------|
| GPTScan (ICSE 2024) | [Paper](https://daoyuan14.github.io/papers/ICSE24_GPTScan.pdf) | Detecting Logic Vulnerabilities |
| VulnScan GPT (JSSS 2024) | [Paper](https://www.oaepublish.com/articles/jsss.2024.21) | LLM-based Detection |
| SmartBugs (ASE 2020) | [GitHub](https://github.com/smartbugs/smartbugs-curated) | Curated Dataset of Solidity Vulnerabilities |

---

**Version:** 5.1
**Last Updated:** 2026-03-12
