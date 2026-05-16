"""
Threat Identification Agent
============================
Tugas: Menganalisis Data Flow Diagram (DFD) atau deskripsi arsitektur
sistem, lalu mengidentifikasi ancaman berdasarkan framework STRIDE.

STRIDE adalah framework klasik dari Microsoft untuk mengkategorikan ancaman:
    S - Spoofing               : peniruan identitas
    T - Tampering              : modifikasi data
    R - Repudiation            : penolakan tanggung jawab
    I - Information Disclosure : kebocoran informasi
    D - Denial of Service      : penolakan layanan
    E - Elevation of Privilege : peningkatan hak akses tidak sah

Output: JSON terstruktur berisi daftar threat per kategori STRIDE,
beserta lokasi (komponen/data flow yang terdampak) dan severity awal.
"""

from crewai import Agent
from crewai.llm import LLM

from src.config import GEMINI_API_KEY, LLM_TEMPERATURE, get_llm_model_string


def create_threat_identification_agent() -> Agent:
    """
    Membuat Threat Identification Agent.

    Agent ini fokus pada analisis sistematis DFD/arsitektur untuk
    mengekstrak threat STRIDE secara terstruktur.

    Returns:
        Agent: CrewAI Agent specialist threat identification.
    """
    llm = LLM(
        model=get_llm_model_string(),
        temperature=LLM_TEMPERATURE,
        api_key=GEMINI_API_KEY,
    )

    return Agent(
        role="STRIDE Threat Identification Specialist",
        goal=(
            "Menganalisis Data Flow Diagram (DFD) atau deskripsi arsitektur "
            "sistem perangkat lunak secara sistematis, dan mengidentifikasi "
            "seluruh ancaman keamanan yang relevan berdasarkan framework "
            "STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, "
            "Denial of Service, Elevation of Privilege). Setiap threat harus "
            "memuat lokasi spesifik (komponen atau data flow yang terdampak), "
            "deskripsi singkat, dan severity awal (Low/Medium/High/Critical)."
        ),
        backstory=(
            "Anda adalah expert dalam metodologi STRIDE dari Microsoft Security "
            "Development Lifecycle. Anda telah melakukan ratusan threat modeling "
            "session untuk berbagai jenis sistem: web application, mobile app, "
            "microservices, IoT, dan sistem perbankan. Anda sangat sistematis "
            "dalam menelusuri setiap elemen DFD — external entities, processes, "
            "data stores, dan data flows — serta mempertimbangkan trust boundary "
            "yang dilewati setiap interaksi. Anda mahir mengaitkan threat dengan "
            "CWE (Common Weakness Enumeration) dan OWASP Top 10. Output Anda "
            "selalu terstruktur, ringkas, dan dapat ditindaklanjuti."
        ),
        llm=llm,
        allow_delegation=False,
        verbose=True,
        max_iter=3,
    )


# === Prompt template untuk Task ===
THREAT_IDENTIFICATION_TASK_PROMPT = """
Analisislah Data Flow Diagram (DFD) sistem perangkat lunak berikut ini secara sistematis,
dan identifikasi seluruh ancaman keamanan menggunakan framework STRIDE.

=== INPUT DFD ===
{dfd_content}
=== END INPUT ===

INSTRUKSI ANALISIS:

1. Identifikasi seluruh elemen DFD:
   - External entities (entitas eksternal)
   - Processes (proses internal)
   - Data stores (penyimpanan data)
   - Data flows (alur data)
   - Trust boundaries (batas kepercayaan)

2. Untuk setiap elemen dan data flow, lakukan analisis STRIDE:
   - S (Spoofing): siapa yang bisa meniru identitas di sini?
   - T (Tampering): data/proses mana yang bisa dimodifikasi tanpa otorisasi?
   - R (Repudiation): aksi apa yang bisa dibantah tanpa jejak audit?
   - I (Information Disclosure): informasi sensitif apa yang berisiko bocor?
   - D (Denial of Service): bagaimana sistem bisa di-DoS di titik ini?
   - E (Elevation of Privilege): bagaimana attacker bisa eskalasi hak akses?

3. Untuk setiap threat yang teridentifikasi, sediakan informasi:
   - id            : identifier unik (mis. "T001", "T002")
   - category      : kategori STRIDE (Spoofing/Tampering/Repudiation/Info Disclosure/DoS/Elevation)
   - title         : judul singkat threat
   - description   : deskripsi 2-3 kalimat
   - location      : komponen atau data flow yang terdampak
   - cwe_reference : CWE ID terkait (mis. "CWE-287") jika ada
   - severity      : Low / Medium / High / Critical
   - rationale     : alasan kenapa threat ini relevan untuk sistem tersebut

OUTPUT FORMAT (WAJIB JSON yang valid, dibungkus dalam triple backticks dengan tag json):

```json
{{
  "system_name": "nama sistem dari DFD",
  "total_threats_identified": <jumlah>,
  "threats": [
    {{
      "id": "T001",
      "category": "Spoofing",
      "title": "...",
      "description": "...",
      "location": "...",
      "cwe_reference": "CWE-287",
      "severity": "High",
      "rationale": "..."
    }}
  ],
  "summary": {{
    "by_category": {{
      "Spoofing": <jumlah>,
      "Tampering": <jumlah>,
      "Repudiation": <jumlah>,
      "Information Disclosure": <jumlah>,
      "Denial of Service": <jumlah>,
      "Elevation of Privilege": <jumlah>
    }},
    "by_severity": {{
      "Critical": <jumlah>,
      "High": <jumlah>,
      "Medium": <jumlah>,
      "Low": <jumlah>
    }}
  }}
}}
```

PENTING:
- Pastikan output adalah JSON yang valid dan bisa di-parse
- Identifikasi minimal 6-10 threat (target coverage semua kategori STRIDE)
- Fokus pada threat yang spesifik untuk sistem ini, bukan generik
- Sertakan threat yang berkaitan dengan aspek kriptografi (mis. weak encryption,
  insecure token handling, password hashing) jika relevan — ini akan menjadi
  input untuk Cryptographic Mitigation Recommender Agent di Phase 2
"""
