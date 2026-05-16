# Arsitektur Framework Multi-Agent AI untuk Threat Modeling

## Visi Penuh (Phase 1 → Phase 3)

Framework ini dirancang sebagai sistem multi-agent berbasis Large Language Model
yang mengotomatisasi proses *threat modeling* pada tahap **Design** dalam
Secure Software Development Lifecycle (SSDLC).

Inti diferensiasi: **Cryptographic Mitigation Recommender Agent** — sebuah agent
khusus yang menghasilkan rekomendasi mitigasi kriptografi spesifik dan terstandar
(mengacu OWASP ASVS V6 + NIST 800-53 SC family), yang belum ada di framework
eksisting (Auspex, ASTRIDE, ThreatGPT, ThreatModeling-LLM, dll).

---

## Arsitektur Tujuan Akhir (Phase 3)

```
                ┌─────────────────────────────────────┐
                │  Input: DFD / Architecture Diagram  │
                │  (Markdown, JSON, atau OpenAPI)     │
                └──────────────────┬──────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │       Orchestrator Agent             │
                │  - Mengkoordinasi alur kerja         │
                │  - Routing antar specialized agents  │
                └──────┬──────────────┬─────────┬──────┘
                       │              │         │
            ┌──────────▼──────┐ ┌─────▼─────┐ ┌─▼──────────────┐
            │ Threat          │ │ Threat    │ │ Compliance     │
            │ Identification  │ │ Classifi- │ │ Mapping        │
            │ Agent (STRIDE)  │ │ cation    │ │ Agent          │
            └──────────┬──────┘ │ Agent     │ └────┬───────────┘
                       │        │ (CVSS)    │      │
                       │        └─────┬─────┘      │
                       ▼              │            │
            ┌─────────────────────────▼────────────▼──┐
            │ ⭐ Cryptographic Mitigation             │
            │    Recommender Agent                    │
            │    + RAG: OWASP ASVS V6                 │
            │    + RAG: NIST 800-53 SC family         │
            │    + RAG: NIST SP 800-57 (Key Mgmt)     │
            │    + RAG: Regulasi Indonesia (PDP, POJK)│
            └─────────────────────┬───────────────────┘
                                  │
                                  ▼
                  ┌─────────────────────────────────┐
                  │  Output: Threat Model Report    │
                  │  - Daftar threat STRIDE         │
                  │  - Mitigasi kripto terstandar   │
                  │  - Compliance mapping           │
                  └─────────────────────────────────┘
```

---

## Arsitektur Phase 1 MVP (Saat Ini)

```
        ┌─────────────────────────────────┐
        │  Input: DFD (Markdown file)     │
        └────────────────┬────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────┐
        │   Orchestrator Agent            │
        │   (Coordinator)                 │
        └────────────────┬────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────┐
        │   Threat Identification Agent   │
        │   (STRIDE Analysis)             │
        └────────────────┬────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────┐
        │   Output: STRIDE Threats (JSON) │
        └─────────────────────────────────┘
```

Yang **belum** ada di Phase 1 MVP:
- ⚠️  Cryptographic Mitigation Recommender Agent → Phase 2
- ⚠️  RAG dengan vector database → Phase 2
- ⚠️  Knowledge base OWASP ASVS / NIST 800-53 → Phase 2
- ⚠️  Threat Classification Agent (CVSS scoring) → Phase 3
- ⚠️  Compliance Mapping Agent → Phase 3
- ⚠️  UI Streamlit → Phase 3

---

## Pilihan Teknologi & Justifikasi

| Komponen | Pilihan | Justifikasi |
|----------|---------|-------------|
| Multi-agent framework | **CrewAI** | Sintaks intuitif, dokumentasi bagus, mendukung sequential & hierarchical process. Alternatif yang dipertimbangkan: AutoGen (Microsoft), LangGraph |
| LLM | **Google Gemini 2.5 Flash** | Free tier yang generous (15 req/menit, 1500/hari), kualitas baik untuk reasoning, latency rendah |
| Vector DB (Phase 2) | **ChromaDB** | Lokal, simple setup, persistent, tidak butuh server eksternal |
| Embedding (Phase 2) | **Gemini text-embedding-004** | Kompatibel dengan stack Gemini, kualitas baik, gratis |
| Programming language | **Python 3.11** | Standar industri AI/ML, ekosistem terlengkap |
| UI (Phase 3) | **Streamlit** | Cepat di-prototype, cocok untuk data app demo |

---

## Alur Kerja Phase 1 MVP

1. **Input DFD** — Pengguna menyediakan deskripsi DFD dalam format Markdown
   (lihat `data/test_dfds/ecommerce_login.md` sebagai contoh)
2. **Orchestrator dipanggil** — mengoordinasi alur (Phase 1: hanya passthrough)
3. **Threat Identification Agent dipanggil** — menganalisis DFD secara sistematis
   menggunakan framework STRIDE
4. **Output JSON terstruktur** — daftar threat dengan field: id, category, title,
   description, location, cwe_reference, severity, rationale
5. **Visualisasi & penyimpanan** — hasil ditampilkan di terminal (Rich) dan
   disimpan ke `outputs/` sebagai file JSON

---

## Diferensiasi dari Framework Eksisting

| Framework | Multi-Agent | Crypto KB | Standar Mapping | Indonesia Context |
|-----------|-------------|-----------|-----------------|-------------------|
| ThreatModeling-LLM (2024) | ✗ | ✗ | Parsial NIST | ✗ |
| Auspex (2025) | ✓ | ✗ | STRIDE/PASTA/LINDDUN | ✗ |
| ASTRIDE (2025) | ✓ | ✗ | STRIDE | ✗ |
| ThreatGPT (2025) | ✓ | ✗ | STRIDE+MITRE+CVE | ✗ |
| PILLAR (2024) | ✓ | ◐ (privacy) | LINDDUN | ✗ |
| STRIDE GPT (2023+) | ✗ | ✗ | STRIDE | ✗ |
| **Framework ini** ⭐ | **✓** | **✓ (Phase 2)** | **STRIDE + ASVS + NIST + Regulasi ID** | **✓ (UU PDP, POJK)** |

---

## Roadmap Pengembangan

### ✅ Phase 1 MVP (Selesai)
- [x] Setup project structure
- [x] CrewAI integration dengan Gemini API
- [x] Orchestrator Agent
- [x] Threat Identification Agent (STRIDE)
- [x] Test DFD contoh (e-commerce login)
- [x] Output JSON + Rich terminal visualization

### 🔄 Phase 2: Komponen Diferensiasi (Selanjutnya)
- [ ] Build knowledge base dari OWASP ASVS V6 Cryptography
- [ ] Setup ChromaDB sebagai vector store
- [ ] Implement Cryptographic Mitigation Recommender Agent dengan RAG
- [ ] Integrasi NIST 800-53 SC family
- [ ] Test case dengan fokus pada threat kripto

### ⏳ Phase 3: Penyempurnaan
- [ ] Threat Classification Agent (CVSS scoring)
- [ ] Compliance Mapping Agent (NIST, ISO, regulasi Indonesia)
- [ ] UI Streamlit
- [ ] Test cases diverse: web app, mobile, IoT, microservices
- [ ] Evaluasi terhadap baseline (manual TM oleh expert)

---

## Referensi Teknis Utama

1. Microsoft. *Threat Modeling with STRIDE*. https://learn.microsoft.com/en-us/security/develop/threat-modeling-tool-threats
2. Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley.
3. NIST. (2020). *NIST SP 800-53 Rev. 5: Security and Privacy Controls*.
4. NIST. (2022). *NIST SP 800-218: Secure Software Development Framework (SSDF) v1.1*.
5. OWASP Foundation. (2024). *OWASP Application Security Verification Standard v5.0*.
6. CrewAI Documentation. https://docs.crewai.com/
7. Google AI Studio (Gemini API). https://ai.google.dev/
