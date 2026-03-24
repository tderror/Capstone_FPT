# Huong Dan Test Local - DarkHotel v6.0

## 1. Khoi Dong Backend

```bash
cd backend
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

uvicorn main:app --reload --port 8000
```

## 2. Khoi Dong Frontend

```bash
cd frontend
npm run dev
```

## 3. Truy Cap

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

---

## 4. Test API voi curl

```bash
# Check backend status
curl http://localhost:8000/

# Upload file test
curl -X POST http://localhost:8000/analyze -F "file=@test.sol"
```

---

## 5. Test Code Mau

### Reentrancy (SWC-107)

```solidity
pragma solidity ^0.4.24;
contract Bad {
    mapping(address => uint) balances;
    function withdraw() public {
        msg.sender.call.value(balances[msg.sender])("");
        balances[msg.sender] = 0;
    }
}
```

Expected: VULNERABLE - Reentrancy (SWC-107)

### Integer Overflow (SWC-101)

```solidity
pragma solidity ^0.4.24;
contract Token {
    mapping(address => uint) balances;
    function transfer(address to, uint amt) public {
        balances[msg.sender] -= amt;
        balances[to] += amt;
    }
}
```

Expected: VULNERABLE - Integer Overflow (SWC-101)

### Safe Contract

```solidity
pragma solidity ^0.8.0;
contract Safe {
    mapping(address => uint256) balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
```

Expected: SAFE (CEI pattern + Solidity 0.8+)

---

## 6. Test RAG System

```bash
cd backend
python -c "
from smart_rag_system import SmartRAGSystem
rag = SmartRAGSystem(persist_directory='./qdrant_db_v7')
stats = rag.get_stats()
print(f'KB: {stats[\"total_cases\"]} entries, version: {stats[\"version\"]}')
"
```

Expected: `KB: 458 entries, version: v6-knowledge-enriched`

## 7. Test Slither

```bash
cd backend
python -c "
from slither_smart_wrapper import SmartSlitherWrapper
slither = SmartSlitherWrapper()
print('Slither wrapper ready')
"
```

---

## 8. Ket Qua Mong Doi

| Input Code | Expected Verdict | Expected SWC |
|------------|-----------------|--------------|
| .call.value() truoc state update, pre-0.8 | VULNERABLE | SWC-107 (Reentrancy) |
| += -= pre-0.8, no SafeMath | VULNERABLE | SWC-101 (Integer Overflow) |
| CEI pattern + Solidity 0.8+ | SAFE | — |
| OpenZeppelin ERC20 | SAFE | — |

---

## 9. Troubleshooting

### Backend khong khoi dong

```bash
# Check .env file co GEMINI_API_KEY
cat backend/.env

# Check Qdrant DB
ls backend/qdrant_db_v7/
```

### Slither khong chay

```bash
solc-select versions
solc-select install 0.8.20
solc-select use 0.8.20
```

### RAG khong detect

- Kiem tra `backend/qdrant_db_v7/` ton tai
- Rebuild neu can: `cd backend && python migrate_to_qdrant_v7.py`

---

**Version:** 6.0
**Last Updated:** 2026-03-24
