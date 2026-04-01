# DarkHotel v7.0 — Quy Trình Hoạt Động Chi Tiết

## Tổng Quan Kiến Trúc

```
+-------------------+         +--------------------+         +-------------------+
|    GIAO DIỆN      |  POST   |    MÁY CHỦ         |         |  CƠ SỞ TRI THỨC  |
|  (Next.js)        | ------> |  (FastAPI)          | <-----> |  (Qdrant + JSON)  |
|  localhost:3000   | /analyze|  localhost:8000      |         |   407 mẫu dữ liệu|
+-------------------+         +--------------------+         +-------------------+
                                       |
                                  [Bước 1: AST]
                                       |
                     +-----------------+-----------------+
                     |  (song song - asyncio.gather)     |
               +-----v-----+                      +------v------+
               |  Slither   |                      |voyage-code-3|
               |  (cục bộ)  |  Bước 2              | (API, 1024d)| Bước 3
               |  Phân tích |                      | Nhúng vector|
               |  tĩnh      |                      +------+------+
               +-----+------+                             |
                     |                              +------v------+
                     |                              |   Qdrant    |
                     |                              | (vector DB) |
                     |                              +------+------+
                     |                                     |
                     +-----------------+-----------------+-+
                                       |
                                  [Bước 4]
                               +------v------+
                               |voyage-rerank|
                               |    -2.5     |
                               | (API,rerank |
                               |  + CRAG)    |
                               +------+------+
                                      |
                                  [Bước 5]
                               +------v------+
                               |  Gemini     |
                               |  2.5 Pro    |
                               |  (API)      |
                               +------+------+
                                      |
                                  [Bước 6]
                               +------v------+
                               | Báo cáo JSON|
                               +-------------+
```

> **Ghi chú kiến trúc**: Hệ thống sử dụng **4 thành phần ML**, trong đó **1 chạy cục bộ**:
>
> | Thành phần | Vai trò | Chi tiết | Chạy ở đâu |
> |---|---|---|---|
> | **voyage-code-3** | Nhúng vector (embedding) | 1024 chiều, 300+ ngôn ngữ lập trình | API (Voyage AI) |
> | **voyage-rerank-2.5** | Xếp hạng lại (reranker) | Instruction-following, code-aware | API (Voyage AI) |
> | **CRAGEvaluator** | Cổng chất lượng RAG | Rule-based (ngưỡng relevance_score) | Cục bộ |
> | **Gemini 2.5 Pro** | Suy luận & phán đoán | Không công bố | API (Google) |
>
> CRAGEvaluator là thành phần duy nhất chạy cục bộ (rule-based, không phải ML).
> Qdrant vector DB cũng chạy cục bộ (embedded mode). Cần kết nối internet
> cho Voyage AI API (embedding + reranking) và Google Vertex AI (LLM).

---

## Quy Trình Xây Dựng Cơ Sở Tri Thức (Chạy một lần duy nhất)

```
Bộ dữ liệu DAppSCAN (608 báo cáo kiểm toán, 21.457 file .sol)
        |
        v
[ingest_dappscan.py]  ───>  ChromaDB v5 (phiên bản cũ, đã xóa)
        |
        v
[export_kb_v5.py]     ───>  darkhotel_knowledge_base_v5.json (458 mẫu, phiên bản cũ)
  (đã xóa)                   Các trường: id, swc_id, swc_name, severity,
        |                                function, line, code_snippet_vulnerable,
        |                                audit_company, source_file
        v
[enrich_knowledge_base.py]  ───>  darkhotel_knowledge_base_v6.json (458 mẫu)
        |                          THÊM MỚI: root_cause, trigger_condition, fix_solution
        |                          (Sinh tự động theo mẫu cho từng loại SWC + trích xuất bằng regex)
        v
[fix_knowledge_base.py]    ───>  darkhotel_knowledge_base_v7.json (407 mẫu)
        |                          Xóa 15 entries trống, 36 trùng lặp, 8 false positive
        v
[migrate_to_qdrant_v8.py]
        |
        |  Với mỗi mẫu dữ liệu:
        |    1. Tạo văn bản tài liệu:
        |       "Vulnerability: {swc_name}\n SWC ID: {swc_id}\n Severity: ...\n
        |        Root Cause: ...\n Trigger: ...\n Fix: ...\n Code:\n{đoạn_mã}"
        |
        |    2. Nhúng vector bằng voyage-code-3 (1024 chiều):
        |       input_type="document" (Voyage API tự xử lý prefix)
        |       Mô hình: Voyage AI voyage-code-3 (API, 300+ ngôn ngữ)
        |
        |    3. Đưa vào Qdrant:
        |       vector: mảng 1024 số thực
        |       payload: {swc_id, swc_name, severity, function, line_number,
        |                 audit_company, source_file,
        |                 code_snippet_vulnerable (tối đa 3000 ký tự),
        |                 root_cause, trigger_condition, fix_solution}
        v
qdrant_db_v8/  (Qdrant chế độ cục bộ, backend SQLite)
  Bộ sưu tập: "darkhotel_v8"
  407 điểm dữ liệu, 1024 chiều, khoảng cách Cosine
```

---

## Thống Kê Cơ Sở Tri Thức

```
+--------------------------------------------------+--------+
| Danh mục                                         | Số lượng|
+--------------------------------------------------+--------+
| SWC-101 Tràn số nguyên (Integer Overflow/Under.) |   173  |
| SWC-107 Tấn công gọi lại (Reentrancy)           |   129  |
| SWC-104 Không kiểm tra giá trị trả về           |   105  |
+--------------------------------------------------+--------+
| TỔNG CỘNG                                        |   407  |
+--------------------------------------------------+--------+
| Nguồn: DAppSCAN (608 báo cáo kiểm toán chuyên nghiệp)    |
| v7-quality-fixed: xóa trùng lặp, entries trống, FP        |
| Các trường bổ sung: root_cause, trigger, fix_solution      |
+------------------------------------------------------------+
```

---

## Khởi Tạo Máy Chủ (khi chạy `uvicorn main:app`)

```
[KHỞI TẠO] Nạp .env (GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_CLOUD_PROJECT,
                     GOOGLE_CLOUD_LOCATION, MODEL_NAME, QDRANT_DB_PATH)
   |
   +---> SolidityASTParser()  — Bộ phân tích cú pháp
   |       - Thử nạp tree_sitter_solidity + tree_sitter
   |       - Nếu thành công: ts_available = True (bộ phân tích chính)
   |       - Regex luôn sẵn sàng (phương án dự phòng)
   |       - Thứ tự ưu tiên: tree-sitter → regex
   |
   +---> SmartSlitherWrapper()  — Trình bọc Slither
   |       - Kiểm tra solc-select đã cài chưa
   |       - Kiểm tra slither đã cài chưa
   |
   +---> SmartRAGSystem(persist_directory="./qdrant_db_v8")  — Hệ thống RAG
   |       |
   |       +---> VoyageCodeEmbeddings()
   |       |       Kết nối Voyage AI API (voyage-code-3, 1024 chiều)
   |       |       Không cần tải model — gọi API qua voyageai SDK
   |       |
   |       +---> QdrantClient(path="./qdrant_db_v8")
   |       |       Kết nối Qdrant cục bộ, xác minh bộ sưu tập "darkhotel_v8"
   |       |       Đọc points_count = 407
   |       |
   |       +---> VoyageReranker()  — Bộ xếp hạng lại
   |       |       Kết nối Voyage AI API (rerank-2.5)
   |       |       Instruction-following, code-aware, không cần tải model
   |       |
   |       +---> CRAGEvaluator()  — Bộ đánh giá CRAG (rule-based, KHÔNG PHẢI model ML)
   |               Chỉ dùng 2 ngưỡng cố định: ĐÚNG >= 0.7, SAI < 0.3
   |
   +---> LLMAnalyzer(project=GOOGLE_CLOUD_PROJECT, location=GOOGLE_CLOUD_LOCATION,
   |               model=MODEL_NAME)  — Bộ phân tích LLM
           Khởi tạo Google GenAI client via Vertex AI
```

---

## Quy Trình Phân Tích (POST /analyze)

### BƯỚC 1: Phân Tích Cú Pháp & Chia Nhỏ Mã Nguồn (AST Chunking)

```
Đầu vào: file .sol (văn bản UTF-8)
   |
   v
ast_parser.parse(code_text)
   |
   |  Thứ tự ưu tiên phân tích:
   |    1. tree-sitter          ──> AST nhanh, không cần biên dịch (chính)
   |    2. regex                ──> Trích xuất hàm cơ bản (dự phòng)
   |
   v
ASTResult {
  contracts: [Contract {name, functions[], state_variables[], modifiers[]}]
  solidity_version: "^0.4.24"
  parse_method: "tree_sitter" | "solc" | "regex"
}
   |
   +---> ast_parser.get_summary(ast_result)
   |       → { total_contracts, total_functions, solidity_version, parse_method }
   |       Tóm tắt tổng quan hợp đồng
   |
   +---> ast_parser.get_function_chunks(ast_result)
   |       → [ {name, contract, code, start_line, end_line, visibility} ]
   |       Danh sách từng hàm kèm mã nguồn
   |
   +---> ast_parser.get_risky_functions(ast_result)
           Lọc các hàm có dấu hiệu rủi ro:
             - has_external_call (regex: .call, .send, .transfer, .delegatecall)
             - has_state_change (regex: ghi vào storage, cập nhật mapping)
             - potential_reentrancy (gọi bên ngoài + thay đổi trạng thái)
             - no_reentrancy_guard (không có modifier nonReentrant)
           Đầu ra: [ {name, contract, code, risk_indicators[], has_external_call,
                       has_state_change, modifiers[]} ]
```

### BƯỚC 2 + BƯỚC 3: Slither + RAG Search (CHẠY SONG SONG)

> **Đánh số 6 bước**: Pipeline có **6 bước logic riêng biệt** (1, 2, 3, 4, 5, 6).
> Bước 2 (Slither) và Bước 3 (RAG Search) là hai bước logic khác nhau nhưng được
> **thực thi đồng thời** bằng `asyncio.gather()` để tiết kiệm thời gian.
> Chúng được gộp trong cùng một mục tài liệu vì chạy song song, nhưng vẫn là
> 2 bước riêng (tổng cộng 6 bước, không phải 5). Kết quả của chúng độc lập —
> chỉ hội tụ tại Bước 4 (Reranking + CRAG) và Bước 5 (LLM).
>
> ```
> Bước 1 ──> Bước 2 ──┐
>                      ├──> Bước 4 ──> Bước 5 ──> Bước 6
>            Bước 3 ──┘
>            (song song với Bước 2)
> ```

```
          asyncio.gather() ─── 2 tác vụ chạy đồng thời ───
          |                         |
          v                         v
  [BƯỚC 2: SLITHER]          [BƯỚC 3: TÌM KIẾM RAG]
          |                         |
          v                         v

=== BƯỚC 2: SLITHER — Phân tích tĩnh ===

slither.get_warnings_for_ai(code_text)
   |
   +---> Phát hiện phiên bản Solidity từ pragma
   +---> Kiểm tra import bên ngoài (@openzeppelin, v.v.)
   |       Nếu có import:
   |         - Ghi nhận các cơ chế bảo vệ (ReentrancyGuard, onlyOwner) TRƯỚC KHI xóa
   |         - Xóa import + kế thừa để biên dịch được
   |
   +---> Ghi file .sol tạm thời
   +---> KHÓA (threading + file lock liên tiến trình) ──> solc-select use {phiên_bản}
   |       📝 File lock dùng time.time() (wall-clock) thay vì time.monotonic()
   |       vì so sánh với os.path.getmtime() (cũng wall-clock) để phát hiện khóa cũ.
   +---> Chạy: slither temp.sol --json output.json
   +---> Phân tích kết quả JSON
   |
   v
Đầu ra (một trong các trường hợp):
  ["[High] reentrancy (line 45): ..."]           # Slither phát hiện vấn đề
  ["No vulnerabilities detected by Slither"]       # Slither không tìm thấy gì
  ["WARNING SLITHER UNAVAILABLE: ..."]             # Slither lỗi (tín hiệu rõ ràng!)

   *** Xử lý cơ chế bảo vệ bị xóa ***
   Nếu code gốc có import (@openzeppelin) và dùng ReentrancyGuard/onlyOwner:
   → Các modifier này bị XÓA để Slither biên dịch được
   → Nhưng thông tin bảo vệ được GHI NHẬN TRƯỚC KHI XÓA
   → Gắn thêm vào warnings[]: "⚠️ NOTE: Original code uses
     ReentrancyGuard/nonReentrant (removed for Slither compilation).
     Verify if above findings are still valid with these protections."

   📝 Luồng truyền thông tin bảo vệ đến LLM:
   ┌────────────────────────────────────────────────────────────────┐
   │ Bước 2 (Slither)                                              │
   │   stripped_protections = ["ReentrancyGuard/nonReentrant"]      │
   │   warnings[] += "⚠️ NOTE: Original code uses ..."             │
   │                           │                                    │
   │                           v                                    │
   │ main.py: slither_warnings (biến chứa toàn bộ warnings[])      │
   │                           │                                    │
   │                           v                                    │
   │ Bước 5 (LLM): llm.analyze(code, slither_warnings, ...)        │
   │   → slither_warnings được đưa VÀO PROMPT dưới phần            │
   │     "## STATIC ANALYSIS (Slither):"                            │
   │   → LLM đọc được chuỗi "⚠️ NOTE: Original code uses          │
   │     ReentrancyGuard..." và BIẾT code gốc có bảo vệ            │
   │   → LLM có thể đánh giá: Slither warning do thiếu modifier    │
   │     (đã bị strip) hay do lỗ hổng thực sự                      │
   └────────────────────────────────────────────────────────────────┘


=== BƯỚC 3: TÌM KIẾM RAG — Tìm mẫu tương tự trong cơ sở tri thức ===

run_rag_search()
   |
   +---> NẾU có function_chunks (tất cả hàm, KHÔNG chỉ risky):
   |       VỚI MỖI hàm trong function_chunks:
   |         search_code = func['code_with_context']  (mã nguồn + state variables)
   |         search_query = "Solidity function {name} in contract {contract}:\n{search_code}"
   |         top_k = 15 nếu func['priority'] > 0 (hàm rủi ro)
   |         top_k = 5  nếu func['priority'] == 0 (hàm thường)
   |         |
   |         v
   |       smart_rag.search_similar(search_query, top_k, filter_type=None)
   |         |
   |         +---> VoyageCodeEmbeddings.embed_query(mã_nguồn)
   |         |       input_type="query" (Voyage API tự thêm prefix phù hợp)
   |         |       Đầu ra: vector 1024 chiều
   |         |
   |         |       📝 Tại sao input_type khác nhau? (Asymmetric Embedding)
   |         |       voyage-code-3 dùng asymmetric embedding (nhúng bất đối xứng),
   |         |       một kỹ thuật phổ biến trong information retrieval:
   |         |       - Khi NHÚNG tài liệu (ingest): input_type="document"
   |         |       - Khi NHÚNG truy vấn (search): input_type="query"
   |         |       Voyage API tự xử lý prefix nội bộ dựa trên input_type,
   |         |       giúp mô hình phân biệt vai trò của vector (tài liệu vs truy vấn).
   |         |       Đây là thiết kế theo tài liệu chính thức của Voyage AI.
   |         |       KHÔNG PHẢI mâu thuẫn — là có chủ đích.
   |         |
   |         +---> Qdrant.query_points(query_vector, limit=top_k, score_threshold=0.15)
   |         |       limit = top_k (5 hoặc 15, truyền thẳng, KHÔNG nhân 3)
   |         |       score_threshold=0.15 (ngưỡng thấp, để reranker
   |         |         quyết định relevance thay vì hard-filter ở bi-encoder)
   |         |       filter_type=None (KHÔNG filter theo loại vuln, để vector
   |         |         similarity tự xử lý relevance)
   |         |       Trả về: tối đa top_k kết quả [{score, payload}]
   |         |
   |         +---> Định dạng kết quả:
   |         |       { vulnerability_type, swc_id, severity, similarity,
   |         |         function, line_number, audit_company, source_file,
   |         |         code_snippet_vulnerable, root_cause, trigger_condition,
   |         |         fix_solution }
   |         |
   |         +---> Sắp xếp theo độ tương đồng (cosine similarity)
   |         |
   |         +---> Gắn nhãn source_function, source_contract cho mỗi kết quả
   |
   +---> NGƯỢC LẠI (không có function_chunks):
   |       search_query = code_text[:3000]  (lấy 3000 ký tự đầu)
   |       top_k = 15, cùng quy trình như trên nhưng chỉ một lần tìm kiếm
   |
   v
rag_candidates: [tổng hợp kết quả từ tất cả hàm]
  Ví dụ: 2 hàm risky × 15 + 3 hàm thường × 5 = 45 kết quả thô

   📝 Luồng dữ liệu chi tiết:
   Qdrant trả về tối đa top_k per hàm (5 hoặc 15)
   → Gộp tất cả kết quả
   → Dedup (bước dưới): giảm trùng lặp
   → Rerank (Bước 4): chọn 5 tốt nhất cuối cùng

   |
   +---> LOẠI BỎ TRÙNG LẶP theo (vulnerability_type, swc_id, source_function, audit_company)
   |       Giữ tối đa 3 mẫu cho mỗi khóa duy nhất
   |
   v
unique_candidates: [kết quả đã loại trùng]


```

### BƯỚC 4: Xếp Hạng Lại Bằng Voyage Reranker + Cổng CRAG

```
unique_candidates (từ Bước 3, sau khi loại trùng)
   |
   v
=== XÂY DỰNG RERANK QUERY (trước khi gọi reranker) ===

_infer_filter_type(code):
   - .call{value:} hoặc .call.value()  →  "Reentrancy"
   - .send() hoặc .call()              →  "UncheckedReturnValue"
   - Phép tính (+,-,*) không SafeMath
     + pragma < 0.8.0                  →  "IntegerUO"
   - Không khớp mẫu nào               →  None

NẾU có hàm rủi ro:
   Dùng tối đa 3 hàm rủi ro đầu tiên (risky_functions[:3]).
   📝 Tóm tắt nhiều hàm thay vì nối toàn bộ code (query hiệu quả hơn cho reranker).

   Với mỗi hàm: tạo summary "function {name} in {contract} ({indicators})"
   Suy luận loại vuln từ code pattern (_infer_filter_type)
   Thêm Slither context nếu có (slither_vuln_types)

   rerank_query = (
     "Solidity vulnerabilities: {func_summaries}.{vuln_hint}{slither_context} "
     "Code: {top_funcs[0].code[:300]}"
   )

NGƯỢC LẠI (không có hàm rủi ro):
   Suy luận loại vuln từ toàn bộ code (_infer_filter_type)

   rerank_query = (
     "Smart contract security audit of Solidity code.{vuln_hint}{slither_context} "
     "Checking for reentrancy, unchecked return values, and integer overflow "
     "vulnerabilities. Code: {code_text[:500]}"
   )

   |
   v
=== 4a: XẾP HẠNG LẠI BẰNG VOYAGE RERANKER ===

smart_rag.reranker.rerank(query=rerank_query, candidates, top_k=5)
   |
   +---> Với mỗi ứng viên:
   |       Tạo doc_text qua _build_doc_text():
   |         "Solidity vulnerability: {loại} ({swc}). in function {func}.
   |          Root cause: {nguyên_nhân}. Trigger: {trigger}. Fix: {fix}.
   |          Code: {đoạn_mã[:400]}"
   |
   +---> Thêm instruction prefix vào query:
   |       instructed_query = "Find Solidity smart contract vulnerability patterns
   |         matching this code. Focus on reentrancy, integer overflow, and
   |         unchecked return values.\n\n" + rerank_query[:8000]
   |
   +---> Voyage AI rerank API:
   |       vo.rerank(query=instructed_query, documents=[doc_texts], model="rerank-2.5", top_k=5)
   |       Đầu ra: relevance_score đã chuẩn hóa [0, 1] cho mỗi ứng viên
   |
   |       📝 Tại sao dùng voyage-rerank-2.5?
   |       voyage-rerank-2.5 là reranker instruction-following của Voyage AI:
   |       - Hỗ trợ code-aware reranking (hiểu cả code lẫn NL)
   |       - Instruction-following: query prefix hướng dẫn model tập trung vào
   |         vulnerability patterns cụ thể (reentrancy, overflow, unchecked return)
   |       - 32K context window per document
   |       - Trả về relevance_score đã chuẩn hóa [0,1] — không cần sigmoid
   |
   |       **Ưu điểm so với ms-marco (phiên bản cũ):**
   |       1. Code-aware: hiểu cú pháp Solidity, không chỉ NL
   |       2. Instruction-following: có thể hướng dẫn focus vào vuln types cụ thể
   |       3. Pre-calibrated scores: relevance_score [0,1] trực tiếp, không cần
   |          sigmoid normalization hay combined_score weighting
   |       4. Larger context: 32K vs 512 tokens
   |
   +---> Sắp xếp theo relevance_score, lấy 5 kết quả tốt nhất
   |
   v
reranked_results: 5 ứng viên hàng đầu với điểm bi_encoder + relevance_score

   |
   v
=== 4b: CỔNG CRAG (Corrective RAG — RAG có điều chỉnh) ===

   ⚠️ QUAN TRỌNG: CRAGEvaluator KHÔNG PHẢI mô hình ML!
   ┌─────────────────────────────────────────────────────────────┐
   │ CRAGEvaluator là bộ đánh giá DỰA TRÊN QUY TẮC (rule-based)│
   │ gồm các câu lệnh if/elif so sánh relevance_score          │
   │ (từ voyage-rerank-2.5, đã chuẩn hóa [0,1]) với ngưỡng:   │
   │                                                             │
   │   [1] max(relevance_score) >= 0.7  → CORRECT               │
   │   [2] max(relevance_score) >= 0.3  → AMBIGUOUS             │
   │   [3] max(relevance_score) <  0.3  → INCORRECT             │
   │                                                             │
   │ KHÔNG có mô hình ML riêng, KHÔNG có trọng số huấn luyện.   │
   │ KHÔNG còn bi-encoder floor check (voyage-rerank-2.5 hiểu   │
   │ code nên không cần workaround cho NL-only reranker).        │
   │ KHÔNG còn combined_score weighting (relevance_score đã      │
   │ pre-calibrated từ Voyage API).                              │
   │                                                             │
   │ Ý tưởng lấy cảm hứng từ bài báo CRAG (Yan et al.,         │
   │ arXiv:2401.15884), nhưng triển khai đơn giản hóa:          │
   │ dùng ngưỡng cố định thay vì huấn luyện T5-large evaluator. │
   └─────────────────────────────────────────────────────────────┘

smart_rag.crag.evaluate(reranked_results)
   |
   +---> max_relevance = max(c.relevance_score for c in reranked_results)
   |
   +---> Quyết định (đánh giá top-down, match đầu tiên thắng):
   |
   |   [1] max_relevance >= 0.7  ──>  "ĐÚNG" (CORRECT)
   |         Tất cả kết quả được gửi cho LLM làm bằng chứng
   |         (Bằng chứng RAG có độ liên quan cao)
   |
   |   [2] max_relevance >= 0.3  ──>  "MƠ HỒ" (AMBIGUOUS)
   |         Chỉ các kết quả có relevance_score >= 0.3 được gửi
   |         (Liên quan một phần, lọc bỏ kết quả yếu)
   |
   |   [3] max_relevance < 0.3  ──>  "SAI" (INCORRECT)
   |         KHÔNG gửi bằng chứng nào cho LLM
   |         (RAG không liên quan, LLM tự đánh giá bằng kiến thức nội tại)
   |
   v
evidence_for_llm: [0-5 ứng viên đã lọc] hoặc []
crag_action: "CORRECT" | "AMBIGUOUS" | "INCORRECT"
```

### BƯỚC 5: Suy Luận Chuỗi Tư Duy (Chain-of-Thought) Bằng LLM

```
llm.analyze(code_text, slither_warnings, evidence_for_llm, solidity_version)
   |
   v
=== XÂY DỰNG PROMPT ===

create_advanced_prompt():
   |
   +---> PHẦN SLITHER:
   |       Nếu có cảnh báo:    "[High] reentrancy at line 45: ..."
   |       Nếu Slither sạch:   "No vulnerabilities detected by Slither"
   |       Nếu Slither lỗi:    "SLITHER UNAVAILABLE: ... AI phải tự kiểm tra"
   |
   +---> PHẦN RAG (có bổ sung tri thức):
   |       Với mỗi mẫu bằng chứng (tối đa 3):
   |         "Case 1: Reentrancy (SWC-107) - Similarity: 0.85"
   |         "Severity: High"
   |         "Root Cause: Gọi bên ngoài trước khi cập nhật trạng thái..."
   |         "Trigger Condition: Kẻ tấn công triển khai hợp đồng để..."
   |         "Fix Solution: Dùng mẫu Checks-Effects-Interactions..."
   |         "Vulnerable Code: function withdraw() { ... }"
   |       HOẶC: "No similar cases found" (nếu CRAG = SAI)
   |
   +---> EXPERT RULES FROM AUDIT KNOWLEDGE BASE (Tier 2 — chỉ khi có RAG):
   |       Các quy tắc chuyên gia từ 407 audit cases:
   |       - Safe Pattern Recognition (khi nào KHÔNG báo lỗi)
   |       - Severity Calibration (từ dữ liệu audit thực tế)
   |       - Exploit Verification (từ trigger conditions lịch sử)
   |       📝 Tier 2 rules chỉ được inject khi RAG evidence có sẵn.
   |       Khi không có RAG → LLM chỉ có Tier 1 (basic checklist) → FP cao hơn.
   |
   +---> MÃ NGUỒN CẦN PHÂN TÍCH: toàn bộ mã hợp đồng
   |
   +---> DANH SÁCH KIỂM TRA CÓ HỆ THỐNG (3 loại lỗ hổng):
   |       1. Reentrancy (SWC-107): kiểm tra .call{value:} trước khi cập nhật trạng thái
   |       2. Integer Overflow (SWC-101): TRƯỚC TIÊN kiểm tra pragma >= 0.8.0
   |       3. Unchecked Return Value (SWC-104): kiểm tra .send()/.call() có kiểm tra trả về
   |
   +---> ĐỊNH DẠNG ĐẦU RA: schema JSON nghiêm ngặt
   |       { verdict, confidence, primary_vulnerability, secondary_warnings,
   |         vulnerabilities[], reasoning }
   |
   +---> 7 QUY TẮC (anti-hallucination):
           1. Chỉ xuất JSON hợp lệ, không markdown
           2. Kiểm tra đủ 3 loại SWC — không bỏ sót
           3. Chỉ báo cáo SWC-107, SWC-101, SWC-104 (ngoài scope thì bỏ)
           4. Nếu 3 check đều NO → verdict PHẢI là "SAFE"
           5. Phải có bằng chứng cụ thể (exploit scenario)
           6. primary_vulnerability = 1 finding nguy hiểm nhất
           7. Không "báo cho an toàn" — chỉ báo khi CHỨNG MINH được
   |
   v
=== GỬI ĐẾN GEMINI 2.5 PRO ===

Thêm tiền tố JSON-only (không dùng system role — vai trò đã định nghĩa trong prompt):
  full_prompt = "IMPORTANT: Output ONLY valid JSON — no markdown, no commentary.\n\n" + prompt

Google GenAI SDK via Vertex AI:
  client.models.generate_content(model="gemini-2.5-pro", contents=full_prompt)
  Thử lại: 5 lần với thời gian tăng dần theo exponential backoff (60s, 120s, 240s, 480s)
   |
   v
=== HẬU XỬ LÝ ===

1. _parse_json_response(response.text)
     Chiến lược 1: Phân tích JSON trực tiếp
     Chiến lược 2: Trích xuất từ khối ```json ... ```
     Chiến lược 3: Tìm cặp { ... } ngoài cùng trong văn bản

2. _filter_out_of_scope(analysis_json)
     Loại bỏ mọi loại SWC không nằm trong {SWC-107, SWC-101, SWC-104}
     Nếu lỗ hổng chính bị loại, đẩy lên từ danh sách còn lại
     Nếu không còn phát hiện nào, đặt verdict = "SAFE"

3. _filter_pragma_080(analysis_json, solidity_version)
     Nếu Solidity >= 0.8.0: loại bỏ TẤT CẢ phát hiện SWC-101
     Nếu tất cả phát hiện đều là SWC-101, đổi verdict thành "SAFE"
   |
   v
llm_result: {
  success: true,
  analysis: "văn bản phản hồi thô",
  analysis_json: {
    verdict: "VULNERABLE",
    confidence: "HIGH",
    primary_vulnerability: { type, swc_id, severity, location, description,
                             exploit_scenario, recommendation },
    secondary_warnings: [...],
    vulnerabilities: [...],
    reasoning: "Phân tích từng bước..."
  },
  model: "gemini-2.5-pro",
  prompt_tokens: 8500,
  completion_tokens: 1200
}
```

### BƯỚC 6: Tạo Báo Cáo Cuối Cùng

```
Kết hợp tất cả kết quả thành phản hồi JSON:
   |
   v
{
  success: true,
  filename: "Contract.sol",
  pipeline_version: "7.0-6step",

  ai_analysis: "văn bản LLM thô",
  ai_analysis_structured: {                    <-- Kết quả JSON từ LLM
    verdict, confidence, primary_vulnerability,
    secondary_warnings, vulnerabilities, reasoning
  },

  rag_findings: {
    found: true/false,
    vuln_type: "Reentrancy (SWC-107)",
    crag_action: "CORRECT",                    <-- Hành động CRAG
    similar_cases: [                           <-- Từ kết quả xếp hạng lại
      { type, swc_id, severity, similarity,
        function, line_number, audit_company,
        source_file, source_function }
    ],
    total_candidates: 25,
    top_k_ranked: 5,
    version: "v7.0-qdrant-voyage-code-3"
  },

  function_analysis: {
    total_functions: 5,
    risky_functions: 2,
    functions_analyzed: [
      { name, contract, risk_indicators,
        has_external_call, has_state_change, modifiers }
    ]
  },

  summary: {
    total_lines: 120,
    total_functions: 5,
    solidity_version: "^0.4.24",
    functions: ["deposit", "withdraw", "getBalance"]
  },

  slither_analysis: {
    warnings: ["[High] reentrancy (line 45): ..."],
    hints_used: ["reentrancy"],
    total_warnings: 3
  },

  llm_analysis: {
    verdict: "VULNERABLE",
    model: "gemini-2.5-pro",
    tokens: { prompt: 8500, completion: 1200 }
  }
}
```

---

## Quy Trình Hiển Thị Giao Diện (Frontend)

```
Phản hồi POST /analyze
   |
   v
page.tsx phân tích phản hồi:
   |
   +---> BIỂN BÁO KẾT QUẢ
   |       ai_analysis_structured.verdict = "VULNERABLE" hoặc "SAFE"
   |       Màu: đỏ (có lỗ hổng) / xanh lá (an toàn)
   |       Hiển thị: mức độ tin cậy, loại lỗ hổng chính
   |
   +---> THẺ LỖ HỔNG CHÍNH (nếu verdict = VULNERABLE)
   |       primary_vulnerability.type, swc_id, severity
   |       primary_vulnerability.description         — Mô tả lỗ hổng
   |       primary_vulnerability.exploit_scenario     — Kịch bản khai thác
   |       primary_vulnerability.recommendation       — Khuyến nghị sửa
   |
   +---> CẢNH BÁO PHỤ (có thể thu gọn)
   |       secondary_warnings[].type, swc_id, severity, description
   |
   +---> THÔNG BÁO AN TOÀN (nếu verdict = SAFE, không có lỗ hổng chính)
   |       "Không phát hiện lỗ hổng trong 3 danh mục mục tiêu"
   |
   +---> BẢNG SLITHER (có thể thu gọn)
   |       slither_analysis.warnings[]
   |       Mã màu theo mức độ: [High] cam, [Medium] hổ phách, [Low] xanh dương
   |
   +---> BẢNG CƠ SỞ TRI THỨC RAG (có thể thu gọn)
   |       rag_findings.vuln_type
   |       rag_findings.crag_action (CORRECT/AMBIGUOUS/INCORRECT)
   |       rag_findings.similar_cases[]
   |       rag_findings.total_candidates, top_k_ranked
   |
   +---> BẢNG LẬP LUẬN AI (có thể thu gọn)
           ai_analysis_structured.reasoning (hiển thị dưới dạng Markdown)
           HOẶC ai_analysis (văn bản thô dự phòng)
```

---

## Cấu Trúc Thư Mục (Đã Dọn Dẹp)

```
DarkHotel-Capstone/
  backend/
    ── Mã nguồn chính (chạy trong pipeline) ──
    main.py                          # Máy chủ FastAPI + pipeline 6 bước
    ast_parser.py                    # Bộ phân tích: tree-sitter + solc + regex
    smart_rag_system.py              # voyage-code-3 + Qdrant + Reranker + CRAG
    llm_analyzer.py                  # LLM Gemini với prompt Chuỗi Tư Duy
    slither_smart_wrapper.py         # Trình bọc phân tích tĩnh Slither

    ── Script xây dựng dữ liệu (chạy 1 lần) ──
    migrate_to_qdrant_v8.py          # Script: JSON v7 -> Qdrant DB v8 (rebuild nếu cần)

    ── Dữ liệu & cấu hình ──
    darkhotel_knowledge_base_v7.json # 407 mẫu, quality-fixed + enriched v7 (~789KB)
    qdrant_db_v8/                    # Cơ sở dữ liệu vector Qdrant (~3.9MB)
    requirements.txt                 # Các gói Python cần thiết
    .env.example                     # Mẫu biến môi trường

    ── Tài liệu phụ ──
    docs/DATA_PIPELINE.md            # Hướng dẫn pipeline dữ liệu
    docs/SMART_RAG_GUIDE.md          # Hướng dẫn hệ thống RAG
    WORKFLOW.md                      # Workflow phiên bản cũ (tham khảo)
    README.md                        # README backend

  frontend/
    app/page.tsx                     # Trang giao diện chính
    app/layout.tsx                   # Bố cục + metadata
    app/globals.css                  # CSS toàn cục (TailwindCSS)
    package.json                     # Phụ thuộc Node.js
    next.config.ts                   # Cấu hình Next.js
    tsconfig.json                    # Cấu hình TypeScript

  evaluation/
    ── Script đánh giá chính ──
    run_smartbugs_eval.py            # Đánh giá trên SmartBugs dataset (98 hợp đồng)
    run_top200_eval.py               # Đánh giá trên GPTScan-Top200 (225 hợp đồng an toàn)
    run_top10_reentrancy_eval.py     # Đánh giá top 10 reentrancy
    run_safe_contracts_eval.py       # Đánh giá hợp đồng an toàn (23 contracts, false positive)
    analyze_smartbugs_metrics.py     # Tính precision/recall/F1

    ── Script ablation study ──
    run_ablation_only_llm.py         # Ablation: chỉ LLM, không RAG/Slither
    run_ablation_llm_only_smartbugs.py  # Ablation: LLM-only trên SmartBugs
    run_ablation_llm_only_top200.py  # Ablation: LLM-only trên top 200

    ── Kết quả đánh giá ──
    smartbugs_evaluation_results.json
    top200_evaluation_results.json
    top10_reentrancy_results.json
    safe_contracts_evaluation_results.json
    ablation_llm_only_smartbugs_results.json
    ablation_llm_only_top200_results.json
    ablation_only_llm_top10_results.json

    ── Ground truth & dữ liệu ──
    labels.json                      # Nhãn đánh giá
    smartbugs_ground_truth.json      # Ground truth SmartBugs
    safe_contracts_ground_truth.json # Ground truth safe contracts
    ground_truth/                    # Ground truth chi tiết theo danh mục
    external_datasets/               # SmartBugs-Curated, safe_contracts, top_10_reentrancy
    evaluation_summary.txt           # Tóm tắt kết quả

  ── Tài liệu gốc ──
  README.md                          # README chính của dự án
  WORKFLOW_V6.md                     # File này
  START_FRONTEND.bat                 # Script khởi động frontend (Windows)
  docs/SETUP.md                      # Hướng dẫn cài đặt
  docs/DEBUGGING.md                  # Hướng dẫn debug
```

> **Ghi chú**: Các file cũ đã bị xóa trong quá trình dọn dẹp: `export_kb_v5.py`,
> `rebuild_chroma_from_json.py`, `rebuild_kb_filtered.py`, `code_chunker.py`,
> `darkhotel_knowledge_base_v5.json`, `darkhotel_knowledge_base_v6.json`,
> `ingest_dappscan.py`, `enrich_knowledge_base.py`, `fix_knowledge_base.py`,
> `migrate_to_qdrant.py` (v6), `test_local.py`, `backend/evaluation/`,
> thư mục `chroma_db_v5/`, `qdrant_db_v6/`, `temp_knowledge/`.

---

## Bảng Công Nghệ Sử Dụng

```
+---------------------+--------------------------------------------------+
| Thành phần          | Công nghệ                                        |
+---------------------+--------------------------------------------------+
| Giao diện           | Next.js 16, React 19, TailwindCSS 4, lucide-react|
| Máy chủ             | FastAPI 0.128, Python 3.11+, uvicorn              |
| Phân tích cú pháp   | tree-sitter-solidity (chính), solc, regex         |
| Phân tích tĩnh      | Slither + solc-select                             |
| Nhúng vector        | voyage-code-3 (Voyage AI, API, 1024d)             |
| Cơ sở dữ liệu vector| Qdrant chế độ cục bộ (không cần Docker)           |
| Xếp hạng lại       | voyage-rerank-2.5 (Voyage AI, instruction-following)|
| Cổng CRAG           | Rule-based, ngưỡng relevance_score (0.7/0.3) |
| Mô hình ngôn ngữ   | Gemini 2.5 Pro (Google GenAI SDK)                 |
| Cơ sở tri thức      | 407 mẫu từ DAppSCAN (608 báo cáo kiểm toán)     |
| Lỗ hổng mục tiêu   | SWC-107, SWC-101, SWC-104 (3 loại)               |
+---------------------+--------------------------------------------------+
```
