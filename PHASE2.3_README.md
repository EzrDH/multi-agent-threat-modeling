# Phase 2.3 — End-to-End Integration & Comparison Demo

> **Milestone akhir Phase 2** — full pipeline yang menggabungkan semua agen dan menghasilkan **bukti diferensiasi konkret** terhadap framework eksisting.

## 📦 Yang Ditambahkan di Phase 2.3

```
NEW FILES:
├── src/schemas/
│   ├── threat.py                                  ← UPDATED: +priority, +is_crypto_related fields
│   ├── report.py                                  ← NEW: FullReport schema
│   └── __init__.py                                ← UPDATED: re-exports
├── src/agents/
│   ├── threat_classification.py                   ← NEW: Threat Classification Agent
│   └── full_pipeline.py                           ← NEW: E2E pipeline orchestrator
├── scripts/
│   ├── run_phase2_full_pipeline.py                ← NEW: E2E demo dengan 8 threats
│   └── generate_comparison_report.py              ← NEW: Phase 1 vs Phase 2 markdown report
└── tests/
    └── test_e2e_pipeline.py                       ← NEW: E2E smoke test
```

## 🎯 Workflow E2E Phase 2.3

```
INPUT: 8 Threats (5 crypto + 3 non-crypto untuk demonstrate filtering)
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│  STEP 1: Threat Classification Agent (NEW)                   │
│  - Analyze each threat                                       │
│  - Set priority: Critical/High/Medium/Low                    │
│  - Detect is_crypto_related: true/false                      │
│  - Output: classified_threats with rationale                 │
└──────────────────────────────────────────────────────────────┘
   │
   ▼ Filter: is_crypto_related == True
   │
┌──────────────────────────────────────────────────────────────┐
│  STEP 2: Cryptographic Mitigation Recommender (Phase 2.2)   │
│  - For each crypto threat:                                   │
│    1. Query KB (ASVS V11 + NIST SC/IA)                       │
│    2. Generate mitigation with RAG                           │
│  - Output: List[MitigationRecommendation]                    │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│  STEP 3: Aggregate to FullReport                             │
│  - Priority breakdown                                        │
│  - Compliance summary (UU PDP, POJK, OWASP Top 10)           │
│  - Quality metrics (avg confidence, coverage rate)           │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
OUTPUT: FullReport JSON
```

## 🚀 Setup & Usage

### Prasyarat (sudah dilakukan)

- ✅ Phase 1 MVP working
- ✅ Phase 2.1 Knowledge base built (90.5% accuracy)
- ✅ Phase 2.2 Crypto Recommender working (5/5 success)
- ✅ `.env` dengan GEMINI_API_KEY valid
- ✅ Recommended: `GEMINI_MODEL=gemini-2.5-flash-lite` untuk quota lebih besar

### Step 1: Extract Zip ke Project

```powershell
cd "C:\Users\EZRA\Documents\02_Akademik\Poltek_SSN\PERKULIAHAN\SEMESTER 6\metlit\multi-agent-threat-modeling"
.\venv\Scripts\activate

# Extract phase2.3 zip di project folder (overwrite jika sama)
```

### Step 2: Smoke Test (Cepat, ~2 menit)

```powershell
python -m tests.test_e2e_pipeline
```

**Yang akan terjadi:**
- 2 threats di-feed ke pipeline (1 crypto + 1 non-crypto)
- Step 1: Classification → seharusnya TEST-001 di-mark crypto-related, TEST-002 tidak
- Step 2: Mitigation generated untuk TEST-001 saja
- Step 3: Aggregate report

**Expected:**
- 7 quality checks, target ≥80% pass (6/7 atau 7/7)
- TEST-002 (DoS) HARUS di-skip dari crypto mitigation

**Estimasi LLM call:** ~3-5 calls (1 classification + 1-3 mitigation)

### Step 3: Demo Penuh (~5-10 menit)

```powershell
python scripts\run_phase2_full_pipeline.py
```

**Yang akan terjadi:**
- 8 threats diproses (5 crypto + 3 non-crypto)
- Visual display dengan Rich tables menampilkan:
  - Input threats
  - Classification results dengan priority + crypto detection
  - Priority breakdown (Critical/High/Medium/Low)
  - Mitigations generated (5 expected)
  - Compliance summary (ASVS + NIST + UU PDP + POJK + OWASP Top 10)
  - Final summary panel
- Output JSON di `outputs/phase2.3_full_report_*.json`

**Expected output:**
- 8 threats classified
- 5 crypto-related, 3 non-crypto (filtering bekerja)
- 5 mitigations generated (target: 100% success)
- Coverage rate: ~100%
- Avg confidence: ≥0.85

**Estimasi LLM call:** ~6-9 calls (1 classification batch + 5 mitigations)

### Step 4: Generate Comparison Report (~30 detik, NO LLM call)

```powershell
python scripts\generate_comparison_report.py
```

**Yang akan terjadi:**
- Load `phase2.3_full_report_*.json` terbaru
- Generate **side-by-side comparison** Phase 1 baseline vs Phase 2
- Compute quantitative metrics (specificity, citations, compliance)
- Save markdown + JSON metrics

**Output files:**
- `outputs/comparison_phase1_vs_phase2_*.md` (markdown, view di VS Code/Typora)
- `outputs/comparison_metrics_*.json` (metrics for further analysis)

**Estimasi LLM call:** **0** (this script is pure data processing)

### Step 5: View Comparison Report

```powershell
# Buka di VS Code
code outputs\comparison_phase1_vs_phase2_*.md

# Atau convert ke PDF (perlu install pandoc dulu)
pandoc outputs\comparison_phase1_vs_phase2_*.md -o comparison.pdf
```

## 📊 Apa yang Akan Kamu Lihat di Comparison Report

Comparison report (markdown ~200 lines) berisi:

**1. Executive Summary** dengan quantitative table:

| Metrik | Phase 1 | Phase 2 | Peningkatan |
|---|---|---|---|
| Algoritma terspesifikasi | 0 | 13-15 | ∞× |
| Parameter konkret | 0 | 30+ | ∞× |
| Referensi standar | 0 | 15-20 | ∞× |
| Compliance mappings | 0 | 15+ | ∞× |
| Forbidden practices | 0 | 25+ | ∞× |
| Code examples | 0 | 5 | ∞× |
| Detail per mitigation | ~100 chars | ~800 chars | ~8× |

**2. Side-by-side comparison per threat** dalam HTML table format

**3. Aggregated compliance coverage:**
- ASVS V11 controls referenced
- NIST 800-53 controls referenced
- UU PDP No. 27/2022 articles
- POJK No. 11/POJK.03/2022 articles
- OWASP Top 10 categories

**4. Key takeaways** untuk dipakai di:
- Latar Belakang ICP
- Slide defense
- Bab Hasil TA
- Paper publikasi

## 🧪 Quality Metrics Phase 2.3

Pipeline dianggap **PRODUCTION-READY** kalau:

- ✅ E2E smoke test pass ≥80% (6/7 atau 7/7 checks)
- ✅ Full demo: 5/5 atau 4/5 mitigations generated
- ✅ Classification accuracy: crypto vs non-crypto filtering correct
- ✅ Compliance summary: minimal 5 ASVS controls, 3 NIST controls, 1+ UU PDP/POJK
- ✅ Average confidence score: ≥0.85
- ✅ Coverage rate: ≥80%

## 🔧 Troubleshooting

### Error: Threat Classification Agent menghasilkan output tidak lengkap

LLM kadang skip beberapa threat di batch classification. Mitigasi sudah ada:
- Code akan fall back ke `priority=Medium, is_crypto_related=True` untuk threat yang missed
- Log warning di terminal — bisa rerun untuk hasil lebih baik

### Error: Rate limit Gemini

Phase 2.3 demo butuh ~6-9 LLM calls. Kalau pakai `gemini-2.5-flash` (20 RPD), bisa habis cepat.

**Solusi:**
1. Switch ke `gemini-2.5-flash-lite` di `.env` (1000 RPD)
2. Atau tunggu quota reset (~15:00 WIB next day)

### Error: Crypto-related detection inconsistent

Threat Classification Agent kadang missclassify edge cases (mis. "session theft via XSS" — bisa crypto OR non-crypto tergantung framing).

**Solusi:**
1. Cek `rationale` field untuk lihat reasoning
2. Adjust prompt di `threat_classification.py` kalau perlu
3. Manual override di code kalau threat tertentu selalu salah klasifikasi

## 📁 Output Files yang Dihasilkan

Setelah lengkap, di folder `outputs/`:

| File | Source | Ukuran | Kegunaan |
|---|---|---|---|
| `phase2.3_full_report_*.json` | `run_phase2_full_pipeline.py` | ~30-50 KB | Master output untuk analisis |
| `comparison_phase1_vs_phase2_*.md` | `generate_comparison_report.py` | ~10-20 KB | Document untuk ICP/TA |
| `comparison_metrics_*.json` | `generate_comparison_report.py` | ~2 KB | Metrics for charts |

## 🎓 Cara Pakai untuk ICP & TA

### Untuk Latar Belakang ICP (Paragraf 5)

Update Paragraf 5 Latar Belakang dengan bukti empiris terbaru:

> _"...Untuk memvalidasi research gap tersebut, peneliti telah melaksanakan studi pendahuluan dengan implementasi Phase 2 prototype dari Multi-Agent AI Framework yang diusulkan. Prototipe diuji terhadap Data Flow Diagram sistem login e-commerce dengan 8 ancaman teridentifikasi (5 kripto-related, 3 non-kripto). Hasilnya menunjukkan **framework berhasil menghasilkan {N} rekomendasi mitigasi kriptografi spesifik dengan {M} referensi standar (OWASP ASVS V11 + NIST 800-53), serta {K} compliance mappings termasuk UU PDP No. 27/2022 dan POJK No. 11/POJK.03/2022.** Hasil ini secara substantif lebih kaya dibandingkan baseline framework eksisting yang hanya menghasilkan saran generik..."_

### Untuk Slide Defense ICP

Slide 1: "Problem Statement" — tampilkan Phase 1 baseline output
Slide 2: "Our Approach" — arsitektur multi-agent dengan Crypto Recommender
Slide 3: "Comparison Table" — copy dari Executive Summary di markdown report
Slide 4: "Sample Output" — pick 1 threat dan tampilkan side-by-side

### Untuk Bab Hasil TA

- Sub-bab 4.1: Implementasi framework (architecture diagram)
- Sub-bab 4.2: Hasil identifikasi threats (table dari report)
- Sub-bab 4.3: Hasil klasifikasi (priority breakdown chart)
- Sub-bab 4.4: Hasil mitigasi (sample mitigations)
- Sub-bab 4.5: **Analisis komparatif Phase 1 vs Phase 2** (bab inti)
- Sub-bab 4.6: Evaluasi compliance coverage

## 🛣️ Setelah Phase 2.3

Status project setelah Phase 2.3 selesai:

| Phase | Status |
|---|---|
| Phase 1 MVP | ✅ Done |
| Phase 2.1 KB | ✅ Done |
| Phase 2.2 Crypto Recommender | ✅ Done |
| **Phase 2.3 E2E Integration** | **✅ Done (this milestone)** |
| Phase 3 UI + Polish | Optional (post-TA) |

**Prototype Phase 2 LENGKAP** — siap untuk:
- Submit ICP (sebelum 2 Juni 2026)
- Mulai SLR worksheet I.2 (Implementation section)
- Mulai TA writing nanti

## 📚 Architecture Summary (Untuk Dokumentasi)

```
┌──────────────────────────────────────────────────────────────────┐
│              Multi-Agent AI Threat Modeling Framework             │
│                                                                    │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐   │
│  │  Threat ID     │   │   Threat       │   │   Compliance    │   │
│  │  Agent         │──▶│   Classifier   │──▶│   Mapping       │   │
│  │  (Phase 1)     │   │   (Phase 2.3)  │   │   (Aggregated)  │   │
│  └────────────────┘   └────────┬───────┘   └────────────────┘   │
│                                │                                  │
│                                ▼                                  │
│              ┌─────────────────────────────────────┐             │
│              │  Cryptographic Mitigation           │             │
│              │  Recommender Agent (Phase 2.2)      │             │
│              │  ┌─────────────────────────────┐   │             │
│              │  │ RAG: ChromaDB Vector Store  │   │             │
│              │  │  - OWASP ASVS V11 (17 reqs) │   │             │
│              │  │  - NIST 800-53 SC/IA (8)    │   │             │
│              │  └─────────────────────────────┘   │             │
│              └─────────────────────────────────────┘             │
│                                                                    │
│  Output: FullReport JSON                                          │
│   - Threats classified & prioritized                              │
│   - Specific crypto mitigations dengan ASVS/NIST citations        │
│   - Compliance mapping (UU PDP, POJK, OWASP Top 10)               │
└──────────────────────────────────────────────────────────────────┘
```
