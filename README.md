# Multi-Agent AI Framework for Automated Threat Modeling

> **Proyek Initial Concept Paper (ICP) — Phase 1 MVP**
> **Mata Kuliah:** Metodologi Penelitian, Genap 2025/2026
> **Program Studi:** D4 Rekayasa Kriptografi, Politeknik Siber dan Sandi Negara
> **Bidang Minat:** Rekayasa Perangkat Lunak Kripto (RPLK)

Framework Multi-Agent AI untuk otomatisasi *threat modeling* pada tahap Design *Secure Software Development Lifecycle* (SSDLC), dengan fokus diferensiasi pada **Cryptographic Mitigation Recommender Agent** sebagai komponen utama (akan dikembangkan di Phase 2).

## 🎯 Tujuan Phase 1 MVP

Membuktikan *feasibility* arsitektur multi-agent untuk threat modeling dengan implementasi minimal:
- **Orchestrator Agent** — mengoordinasi alur analisis
- **Threat Identification Agent** — mengidentifikasi ancaman STRIDE dari DFD

Phase 2 dan 3 akan menambahkan Cryptographic Mitigation Recommender Agent + RAG knowledge base + agent tambahan.

## 📋 Persyaratan Sistem

- Python 3.10 atau lebih baru (rekomendasi: 3.11)
- ~500 MB ruang disk untuk dependencies
- Koneksi internet (untuk panggilan API Gemini)
- Google Gemini API key (gratis — lihat panduan di bawah)

## 🚀 Setup Cepat

### 1. Clone repository ini

```bash
git clone <url-repo-anda>
cd multi-agent-threat-modeling
```

### 2. Buat virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / Mac
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Dapatkan Gemini API Key (gratis)

1. Buka https://aistudio.google.com/apikey
2. Login dengan akun Google
3. Klik **Create API Key** → pilih atau buat project baru
4. Salin API key (format: `AIza...`)

### 5. Konfigurasi environment variable

```bash
# Salin template
cp .env.example .env

# Edit .env dan masukkan API key kamu
# Buka file .env dan isi:
GEMINI_API_KEY=AIza...isi_dengan_key_kamu...
```

### 6. Jalankan MVP

```bash
python -m src.main
```

Output yang diharapkan: framework akan menganalisis DFD contoh (sistem login e-commerce) dan menghasilkan daftar threat STRIDE.

## 📁 Struktur Project

```
multi-agent-threat-modeling/
├── README.md                          # Dokumen ini
├── requirements.txt                   # Python dependencies
├── .env.example                       # Template untuk API key
├── .gitignore                         # File yang di-ignore Git
├── src/
│   ├── __init__.py
│   ├── config.py                      # Konfigurasi LLM & settings
│   ├── main.py                        # Entry point
│   └── agents/
│       ├── __init__.py
│       ├── orchestrator.py            # Agent koordinator
│       └── threat_identification.py   # Agent identifikasi STRIDE
├── data/
│   └── test_dfds/
│       └── ecommerce_login.md         # DFD contoh untuk testing
└── docs/
    └── architecture.md                # Dokumentasi arsitektur
```

## 🔬 Cara Kerja MVP

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────────────┐
│  Input DFD  │───▶│ Orchestrator     │───▶│ Threat Identification│
│ (Markdown)  │    │ Agent            │    │ Agent                │
└─────────────┘    │ (koordinator)    │    │ (analisis STRIDE)    │
                   └──────────────────┘    └──────────┬───────────┘
                                                      │
                                                      ▼
                                           ┌──────────────────────┐
                                           │ Output:              │
                                           │ STRIDE Threat List   │
                                           │ (terstruktur JSON)   │
                                           └──────────────────────┘
```

## 🛣️ Roadmap

- [x] **Phase 1 MVP** — 2 agent dasar, alur kerja sequential
- [ ] **Phase 2 — Diferensiasi Inti**
  - Cryptographic Mitigation Recommender Agent
  - RAG knowledge base (OWASP ASVS V6 + NIST 800-53 SC)
  - ChromaDB vector store
- [ ] **Phase 3 — Penyempurnaan**
  - Threat Classification Agent
  - Compliance Mapping Agent
  - UI Streamlit
  - Test cases beragam (web app, mobile, IoT, microservices)

## 🧪 Test DFD Contoh

Phase 1 MVP menggunakan DFD sederhana **Sistem Login E-Commerce** dengan:
- 4 entitas (User, Browser, Login Service, Database, Session Manager)
- 6 alur data
- 2 trust boundary

Lihat detail di `data/test_dfds/ecommerce_login.md`.

## 📚 Dokumentasi Tambahan

- **Arsitektur Framework**: `docs/architecture.md`
- **DFD Contoh**: `data/test_dfds/ecommerce_login.md`

## ⚠️ Catatan Penting

1. **Jangan commit `.env`** ke Git. File `.gitignore` sudah meng-handle ini.
2. **Free tier Gemini**: 15 request per menit, 1500 request per hari. Cukup untuk development MVP.
3. **Output LLM tidak deterministik** — running yang sama bisa menghasilkan output yang sedikit berbeda. Ini wajar untuk LLM.

## 📄 Lisensi

Project akademik untuk Mata Kuliah Metodologi Penelitian, Poltek SSN.

## 👤 Penulis

[Nama Anda] — D4 Rekayasa Kriptografi, Poltek SSN
