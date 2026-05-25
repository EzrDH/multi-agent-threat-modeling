"""
Cryptographic Mitigation Recommender Agent
===========================================
Agen spesialis yang menghasilkan rekomendasi mitigasi kriptografi yang:
1. Spesifik (algoritma + parameter, bukan general advice)
2. Terstandar (referensi ke OWASP ASVS 5.0 V11 + NIST 800-53)
3. Compliant (mapping ke UU PDP, POJK, OWASP Top 10)
4. Actionable (panduan implementasi konkret)

Menggunakan RAG (Retrieval-Augmented Generation) via knowledge base ChromaDB.

Ini adalah komponen diferensiasi utama Multi-Agent AI Framework yang
membedakan project ini dari framework eksisting (ThreatModeling-LLM, Auspex,
ASTRIDE, ThreatGPT, PILLAR, ThreatFinderAI).
"""

from typing import Optional

from crewai import Agent, Crew, Process, Task

from src.agents.tools.crypto_kb_tool import CryptoKnowledgeBaseTool
from src.config import GEMINI_MODEL, LLM_TEMPERATURE, get_llm_model_string
from src.schemas.crypto_mitigation import MitigationRecommendation
from src.schemas.threat import Threat


# ============================================================================
# Agent Definition
# ============================================================================

def create_crypto_mitigation_agent(verbose: bool = True) -> Agent:
    """
    Buat Cryptographic Mitigation Recommender Agent.
    
    Args:
        verbose: tampilkan output verbose dari agent (recommended untuk debugging)
    
    Returns:
        CrewAI Agent instance ready to use
    """
    
    kb_tool = CryptoKnowledgeBaseTool()
    
    agent = Agent(
        role="Senior Cryptography Security Architect",
        
        goal=(
            "Menghasilkan rekomendasi mitigasi kriptografi yang SPESIFIK, AKURAT, "
            "dan TERSTANDAR untuk setiap ancaman keamanan yang teridentifikasi. "
            "Rekomendasi harus mencakup algoritma persis (mis. AES-256-GCM, bukan 'enkripsi'), "
            "parameter konkret (mis. 'memory_kib=65536' untuk Argon2id), "
            "dan referensi langsung ke OWASP ASVS 5.0 V11 Cryptography serta "
            "NIST SP 800-53 SC/IA controls."
        ),
        
        backstory=(
            "Anda adalah security architect dengan 15 tahun pengalaman dalam "
            "implementasi kriptografi pada sistem perangkat lunak skala besar. "
            "Anda spesialis dalam OWASP Application Security Verification Standard, "
            "NIST cryptographic guidelines, dan regulasi data protection Indonesia "
            "(UU PDP 27/2022, POJK 11/POJK.03/2022). "
            "\n\n"
            "Filosofi kerja Anda: rekomendasi yang baik HARUS specific dan traceable. "
            "Anda tidak pernah memberikan saran generik seperti 'apply encryption' atau "
            "'use secure channel'. Setiap rekomendasi yang Anda berikan dilengkapi "
            "dengan algoritma persis, parameter konkret, referensi standar, dan "
            "panduan implementasi langkah demi langkah."
            "\n\n"
            "WORKFLOW WAJIB: Sebelum merumuskan rekomendasi mitigasi, Anda HARUS "
            "menggunakan tool 'crypto_knowledge_base_search' untuk mengambil "
            "referensi standar yang relevan. Rekomendasi Anda HARUS mengutip "
            "dari hasil knowledge base tersebut. JANGAN merumuskan rekomendasi "
            "berdasarkan general knowledge saja — selalu konsultasi knowledge base dulu."
        ),
        
        tools=[kb_tool],
        
        llm=get_llm_model_string(),
        
        verbose=verbose,
        
        allow_delegation=False,  # single-agent task, tidak perlu delegate
        
        max_iter=5,  # max iterations untuk tool calling
    )
    
    return agent


# ============================================================================
# Task Definition
# ============================================================================

def create_mitigation_task(threat: Threat, agent: Agent) -> Task:
    """
    Buat Task untuk satu threat.
    
    Args:
        threat: Threat object yang akan dimitigasi
        agent: Cryptographic Mitigation Recommender Agent
    
    Returns:
        CrewAI Task dengan structured output (Pydantic)
    """
    
    description = f"""Analisis ancaman keamanan berikut dan hasilkan rekomendasi mitigasi kriptografi yang lengkap, spesifik, dan terstandar.

=== THREAT YANG AKAN DIMITIGASI ===
- Threat ID: {threat.threat_id}
- Title: {threat.title}
- Description: {threat.description}
- STRIDE Category: {threat.stride_category.value}
- CWE ID: {threat.cwe_id or "Not specified"}
- Affected Components: {", ".join(threat.affected_components) if threat.affected_components else "Not specified"}
- Attack Vector: {threat.attack_vector or "Not specified"}
- Severity: {threat.severity or "Not specified"}

=== INSTRUKSI WAJIB ===

LANGKAH 1 — Knowledge Base Lookup (WAJIB):
Gunakan tool 'crypto_knowledge_base_search' dengan parameter:
- threat_title: "{threat.title}"
- threat_description: "{threat.description}"
- cwe_id: "{threat.cwe_id or ''}"
- top_k: 5

JANGAN skip langkah ini. Hasil tool ini akan menjadi context untuk Langkah 2.

LANGKAH 2 — Rumuskan Rekomendasi Mitigasi:
Berdasarkan HASIL knowledge base dari Langkah 1, susun rekomendasi mitigasi yang mencakup:

1. **Summary** (1-2 kalimat): Apa secara ringkas yang harus dilakukan
2. **Recommended Algorithms** (1 atau lebih):
   - Nama algoritma persis (mis. "Argon2id", BUKAN "secure hash")
   - Kategori (password_hashing/symmetric_encryption/asymmetric_encryption/dst)
   - Parameter konkret dalam bentuk key-value (mis. memory_kib=65536, iterations=3)
   - Justifikasi pemilihan
   - Algoritma yang TIDAK boleh dipakai (forbidden_alternatives)
3. **Standard References** (1 atau lebih):
   - HARUS mengutip dari hasil knowledge base
   - Format: standard (mis. "OWASP ASVS 5.0"), control_id (mis. "V11.4.2"), title, excerpt
4. **Implementation Guidance**:
   - Langkah implementasi konkret (numbered list)
   - Library/tool yang direkomendasikan
   - Hal yang harus dihindari
5. **Compliance Mapping**:
   - Mapping ke UU PDP No. 27/2022 jika applicable
   - Mapping ke POJK No. 11/POJK.03/2022 jika applicable
   - Mapping ke OWASP Top 10:2021 (kemungkinan A02 Cryptographic Failures)
6. **Code Example** (opsional): Contoh kode singkat dalam Python/JavaScript/Java

=== ATURAN KETAT ===

❌ JANGAN gunakan istilah generik seperti "apply encryption", "use secure channel", "implement authentication"
✅ HARUS specific: "Use AES-256-GCM with 96-bit random IV from CSPRNG"

❌ JANGAN rekomendasi tanpa standard reference
✅ HARUS cite ASVS/NIST control ID dari hasil knowledge base

❌ JANGAN parameter generik seperti "use strong key"
✅ HARUS specific: "minimum 256-bit key from os.urandom() or equivalent CSPRNG"

=== OUTPUT FORMAT ===
Output HARUS dalam format JSON yang sesuai schema MitigationRecommendation berikut:
- mitigation_id: "MIT-{threat.threat_id.split('-')[-1] if '-' in threat.threat_id else threat.threat_id}"
- threat_id: "{threat.threat_id}"
- threat_title: "{threat.title}"
- summary: string
- recommended_algorithms: list of CryptoAlgorithm objects
- standard_references: list of StandardReference objects (MIN 1, dari knowledge base)
- implementation_guidance: string (detail)
- compliance_mapping: list of ComplianceMapping objects (UU PDP/POJK/OWASP)
- code_example: optional string
- confidence_score: float 0-1 (berdasarkan relevance KB results)
"""
    
    expected_output = (
        "JSON object yang valid sesuai schema MitigationRecommendation dengan SEMUA field terisi. "
        "Standard references HARUS dari hasil knowledge base, bukan dari general knowledge. "
        "Recommended algorithms HARUS specific dengan parameter konkret. "
        "Compliance mapping HARUS mencakup minimal OWASP Top 10:2021 dan jika relevan UU PDP/POJK."
    )
    
    task = Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
        output_pydantic=MitigationRecommendation,
    )
    
    return task


# ============================================================================
# High-level API
# ============================================================================

class CryptoMitigationRecommender:
    """
    High-level API untuk Cryptographic Mitigation Recommender.
    
    Usage:
        recommender = CryptoMitigationRecommender()
        mitigation = recommender.recommend_for_threat(threat)
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.agent = create_crypto_mitigation_agent(verbose=verbose)
    
    def recommend_for_threat(
        self,
        threat: Threat,
    ) -> MitigationRecommendation:
        """
        Generate mitigasi untuk satu threat.
        
        Args:
            threat: Threat object
        
        Returns:
            MitigationRecommendation object (validated by Pydantic)
        """
        task = create_mitigation_task(threat, self.agent)
        
        crew = Crew(
            agents=[self.agent],
            tasks=[task],
            process=Process.sequential,
            verbose=self.verbose,
        )
        
        result = crew.kickoff()
        
        # CrewAI 0.80+ return CrewOutput dengan .pydantic attribute
        if hasattr(result, "pydantic") and result.pydantic is not None:
            return result.pydantic
        
        # Fallback: parse manual dari raw output (kalau structured output gagal)
        raise RuntimeError(
            f"Failed to get structured Pydantic output from agent. "
            f"Raw output: {result.raw if hasattr(result, 'raw') else result}"
        )
    
    def recommend_for_threats(
        self,
        threats: list[Threat],
    ) -> list[MitigationRecommendation]:
        """
        Generate mitigasi untuk list of threats (sequential).
        
        Args:
            threats: List of Threat objects
        
        Returns:
            List of MitigationRecommendation objects
        """
        mitigations = []
        for i, threat in enumerate(threats, 1):
            if self.verbose:
                print(f"\n{'=' * 70}")
                print(f"  Processing threat {i}/{len(threats)}: {threat.title}")
                print(f"{'=' * 70}")
            
            try:
                mitigation = self.recommend_for_threat(threat)
                mitigations.append(mitigation)
            except Exception as e:
                if self.verbose:
                    print(f"  ❌ Failed to generate mitigation for {threat.threat_id}: {e}")
                # Continue dengan threats lain meski satu gagal
                continue
        
        return mitigations
