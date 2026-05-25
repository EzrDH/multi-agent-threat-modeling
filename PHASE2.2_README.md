# Phase 2.2 — Cryptographic Mitigation Recommender Agent

> **Component diferensiasi utama** dari Multi-Agent AI Framework — agen yang menghasilkan rekomendasi mitigasi kriptografi yang **spesifik, akurat, dan terstandar** dengan RAG.

## 📦 Yang Ditambahkan di Phase 2.2

```
NEW FILES:
├── src/schemas/                              ← NEW package (Pydantic schemas)
│   ├── __init__.py
│   ├── threat.py                             ← Threat input schema
│   └── crypto_mitigation.py                  ← Mitigation output schemas
├── src/agents/
│   ├── tools/                                ← NEW subpackage
│   │   ├── __init__.py
│   │   └── crypto_kb_tool.py                 ← CrewAI tool wrapper untuk KB
│   └── crypto_mitigation_recommender.py      ← NEW core agent
├── scripts/
│   └── run_phase2_demo.py                    ← Demo dengan 5 threat Phase 1
└── tests/
    └── test_crypto_recommender.py            ← Smoke test (1 threat)
```

## 🎯 Apa yang Membuat Agen Ini Berbeda

Berdasarkan analisis ICP, ini adalah **diferensiasi inti** project Anda terhadap framework eksisting:

| Framework Eksisting | Output Mitigasi |
|---|---|
| ThreatModeling-LLM, Auspex, ASTRIDE, ThreatGPT, PILLAR, ThreatFinderAI | "apply encryption", "use secure channel", "implement authentication" (generic) |
| **Project Anda** | **"Argon2id dengan m=64MB, t=3, p=4 sesuai OWASP ASVS V11.4.2 L1 + NIST IA-5(1), wajib per UU PDP Pasal 35 dan POJK 11/POJK.03/2022"** (specific + traceable) |

## 🚀 Setup & Usage

### Prasyarat (sudah dilakukan di Phase 2.1)

- ✅ Phase 1 MVP working (CrewAI + Gemini)
- ✅ Knowledge base di-build (`scripts/build_knowledge_base.py`)
- ✅ `tests/test_kb_retrieval.py` pass dengan accuracy ≥60%

### Step 1: Extract dan Replace File

Extract zip Phase 2.2 ke folder project (overwrite file yang sama):

```powershell
# Pastikan kamu di project folder
cd "C:\Users\EZRA\Documents\02_Akademik\Poltek_SSN\PERKULIAHAN\SEMESTER 6\metlit\multi-agent-threat-modeling"

# Activate venv
.\venv\Scripts\activate

# Extract zip ke folder ini (overwrite jika ada)
```

### Step 2: Smoke Test (Cepat, 1 Menit)

Test ringan dengan 1 threat untuk validasi cepat:

```powershell
python -m tests.test_crypto_recommender
```

**Expected:**
- Agent jalan dengan verbose output (kelihatan tool call, LLM reasoning, dst)
- Output `Mitigation generated` dengan ID `MIT-001`
- Quality validation 6 check, target ≥80% pass (mis. 5/6 atau 6/6)
- Mitigation kelihatan specific (mengandung Argon2id, bcrypt, atau PBKDF2)

**Waktu: ~30-60 detik** (1 threat × 1 KB lookup × 1 LLM generation)

### Step 3: Demo Penuh (5 Menit)

Run rekomendasi untuk 5 threat dari Phase 1 MVP:

```powershell
python scripts\run_phase2_demo.py
```

**Expected:**
- 5 threat diproses sequential
- Per threat: ~30-60 detik
- Total: ~3-5 menit
- Output: 5 mitigation lengkap di terminal + file JSON di `outputs/`

**Optional flags:**
```powershell
# Run satu threat saja
python scripts\run_phase2_demo.py --threat THR-002

# Less verbose output
python scripts\run_phase2_demo.py --quiet
```

### Step 4: Inspect Output JSON

File output ada di `outputs/phase2_mitigations_YYYYMMDD_HHMMSS.json`. Cek satu mitigation:

```powershell
type outputs\phase2_mitigations_*.json | more
```

Strukturnya:
```json
{
  "mitigations": [
    {
      "mitigation_id": "MIT-001",
      "threat_id": "THR-001",
      "threat_title": "Weak Password Hashing",
      "summary": "Replace MD5 with Argon2id ...",
      "recommended_algorithms": [
        {
          "name": "Argon2id",
          "category": "password_hashing",
          "parameters": {"memory_kib": "65536", "iterations": "3", "parallelism": "4"},
          "rationale": "Memory-hard function, NIST-compliant...",
          "forbidden_alternatives": ["MD5", "SHA-1", "plain SHA-256"]
        }
      ],
      "standard_references": [
        {
          "standard": "OWASP ASVS 5.0",
          "control_id": "V11.4.2",
          "title": "Password Hashing Functions",
          "level": "1"
        },
        {
          "standard": "NIST SP 800-53 Rev.5",
          "control_id": "IA-5(1)",
          "title": "Authenticator Management - Password-Based Authentication"
        }
      ],
      "compliance_mapping": [
        {
          "regulation": "OWASP Top 10:2021",
          "article_section": "A02:2021",
          "requirement_summary": "Cryptographic Failures"
        }
      ],
      "implementation_guidance": "...",
      "confidence_score": 0.87
    }
  ]
}
```

## 🧰 Cara Pakai Programmatically

```python
from src.agents.crypto_mitigation_recommender import CryptoMitigationRecommender
from src.schemas.threat import Threat, StrideCategory

# Initialize agent (lazy load KB)
recommender = CryptoMitigationRecommender(verbose=False)

# Build threat (atau load dari JSON Phase 1 MVP output)
threat = Threat(
    threat_id="MY-001",
    title="My Custom Threat",
    description="Description of my threat...",
    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
    cwe_id="CWE-916",
)

# Generate mitigation
mitigation = recommender.recommend_for_threat(threat)

# Access structured fields
print(mitigation.summary)
print(mitigation.recommended_algorithms[0].name)
print(mitigation.standard_references[0].control_id)

# Atau serialize ke JSON
print(mitigation.model_dump_json(indent=2))
```

## 🔧 Troubleshooting

### Error: `ModuleNotFoundError: No module named 'src.schemas'`
Pastikan struktur folder lengkap. Cek:
```powershell
dir src\schemas\
# Harus ada: __init__.py, threat.py, crypto_mitigation.py
```

### Agent gagal generate structured output (Pydantic validation error)
Kemungkinan: LLM Gemini output tidak match schema. Solusi:
1. Cek output mentah di log verbose (cari "raw" output)
2. Coba rerun (LLM sometimes flaky)
3. Tune prompt di `create_mitigation_task()` kalau persisten

### Agent skip tool call (tidak query KB)
Cek prompt task — pastikan "LANGKAH 1 WAJIB" instruksi masih ada. Kalau agent skip, output quality akan turun.

### Rate limit Gemini
Free tier: 15 requests/menit untuk LLM, 100 untuk embedding. Demo 5 threats biasanya OK karena ada delay antar request. Kalau hit limit, tunggu 1 menit lalu rerun.

## 📊 Quality Metrics

Phase 2.2 dianggap **READY untuk Phase 2.3** kalau:

- ✅ `test_crypto_recommender.py` lulus ≥80% quality checks (5/6 atau 6/6)
- ✅ `run_phase2_demo.py` selesai untuk minimal 4/5 threats
- ✅ Output mitigation kelihatan specific (mengandung nama algoritma persis, parameter konkret)
- ✅ Setiap mitigation punya minimum 1 standard reference dari KB
- ✅ JSON output bisa di-parse ulang dengan Pydantic tanpa error

## 🛣️ Next Steps

Setelah Phase 2.2 verified:
- [ ] **Phase 2.3** — Update orchestrator untuk integrate Crypto Recommender ke main pipeline
- [ ] **Phase 2.3** — Add Threat Classification Agent (priority classifier)
- [ ] **Phase 2.3** — End-to-end test: DFD → Threat ID → Classification → Crypto Mitigation → JSON output
- [ ] **Phase 2.3** — Comparative analysis: Phase 1 output vs Phase 2 output (sebelum vs sesudah ada Crypto Recommender)

Phase 2.3 akan menghasilkan **demo komparatif** yang menunjukkan diferensiasi project secara empiris — basis untuk bab Hasil Penelitian di laporan TA.
