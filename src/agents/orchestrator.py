"""
Orchestrator Agent
==================
Tugas: Mengoordinasi alur analisis threat modeling antar-agent.
Pada Phase 1 MVP, agent ini berperan sebagai koordinator yang:
  1. Menerima input DFD/arsitektur
  2. Mengarahkan Threat Identification Agent
  3. Menyusun ringkasan hasil

Pada Phase 2+, akan dikembangkan untuk:
  - Mengoordinasi Cryptographic Mitigation Recommender
  - Mengelola pemanggilan multi-agent yang lebih kompleks
"""

from crewai import Agent
from crewai.llm import LLM

from src.config import GEMINI_API_KEY, LLM_TEMPERATURE, get_llm_model_string


def create_orchestrator_agent() -> Agent:
    """
    Membuat Orchestrator Agent dengan konfigurasi default.

    Returns:
        Agent: CrewAI Agent untuk koordinasi alur threat modeling.
    """
    llm = LLM(
        model=get_llm_model_string(),
        temperature=LLM_TEMPERATURE,
        api_key=GEMINI_API_KEY,
    )

    return Agent(
        role="Threat Modeling Orchestrator",
        goal=(
            "Mengoordinasi proses analisis threat modeling secara menyeluruh "
            "pada tahap Design Secure Software Development Lifecycle. "
            "Memastikan setiap specialized agent menerima input yang tepat "
            "dan menyusun hasil akhir yang terstruktur dan dapat ditindaklanjuti."
        ),
        backstory=(
            "Anda adalah arsitek keamanan senior dengan pengalaman 15 tahun "
            "memimpin tim threat modeling di organisasi besar. Anda menguasai "
            "framework Microsoft SDL, OWASP SAMM, NIST SSDF SP 800-218, dan "
            "ISO/IEC 27034. Spesialisasi Anda adalah mengorkestrasi tim "
            "specialist untuk menghasilkan threat model yang komprehensif "
            "dengan rekomendasi mitigasi yang dapat ditindaklanjuti. "
            "Anda terbiasa bekerja dengan DFD, trust boundary, dan arsitektur "
            "sistem yang kompleks."
        ),
        llm=llm,
        allow_delegation=False,  # Pada Phase 1, alur sequential, belum perlu delegation
        verbose=True,
        max_iter=3,
    )
