"""
Threat Classification Agent
============================
Agen yang melakukan klasifikasi ancaman:
1. Priority Level: Critical / High / Medium / Low berdasarkan severity & exploitability
2. Crypto Relevance: True jika ancaman bisa dimitigasi dengan kontrol kriptografi

Output:
- Untuk threats yang `is_crypto_related=True` → akan diteruskan ke
  Cryptographic Mitigation Recommender Agent
- Untuk threats yang `is_crypto_related=False` → log saja, tidak diteruskan ke
  Crypto Recommender (mis. DoS, business logic flaws)
"""

from crewai import Agent, Crew, Process, Task

from src.config import get_llm_model_string
from src.schemas.threat import (
    ClassificationOutput,
    ClassifiedThreat,
    Threat,
    ThreatPriority,
)


# ============================================================================
# Agent Definition
# ============================================================================

def create_threat_classification_agent(verbose: bool = True) -> Agent:
    """
    Buat Threat Classification Agent.
    """
    
    agent = Agent(
        role="Security Risk Assessment Analyst",
        
        goal=(
            "Mengklasifikasikan setiap ancaman teridentifikasi berdasarkan dua dimensi: "
            "(1) priority level (Critical/High/Medium/Low) berdasarkan severity dan exploitability, "
            "dan (2) crypto relevance (apakah ancaman tersebut bisa dimitigasi "
            "dengan kontrol kriptografi seperti enkripsi, hashing, signing, key management, "
            "transport security, atau random number generation)."
        ),
        
        backstory=(
            "Anda adalah analis keamanan dengan pengalaman luas dalam threat modeling dan "
            "risk assessment. Anda mampu dengan cepat menilai severity dan exploitability "
            "ancaman, serta menentukan kontrol kriptografi mana yang relevan."
            "\n\n"
            "PRIORITY CLASSIFICATION GUIDELINES:\n"
            "- **Critical**: Ancaman yang bisa langsung menyebabkan complete system compromise, "
            "data breach massive, atau authentication bypass. Mis. JWT alg:none, hardcoded keys, "
            "plaintext password storage.\n"
            "- **High**: Ancaman dengan dampak signifikan tapi memerlukan kondisi khusus, "
            "atau yang affecting subsystem penting. Mis. weak password hashing, weak TLS config, "
            "predictable tokens.\n"
            "- **Medium**: Ancaman dengan dampak moderate atau memerlukan akses prerequisite. "
            "Mis. cleartext internal communication (membutuhkan network access dulu), "
            "weak random for non-critical functions.\n"
            "- **Low**: Ancaman dengan dampak minimal atau sangat kontekstual. Mis. timing attacks "
            "yang tidak praktis di production environment."
            "\n\n"
            "CRYPTO RELEVANCE GUIDELINES:\n"
            "Ancaman dianggap CRYPTO-RELATED kalau bisa dimitigasi dengan salah satu dari:\n"
            "- Encryption (symmetric/asymmetric): AES, ChaCha20, RSA, ECC\n"
            "- Hashing & MAC: Argon2, bcrypt, PBKDF2, SHA-256+, HMAC\n"
            "- Digital signatures: RSA-PSS, ECDSA, EdDSA\n"
            "- Key management: HSM, KMS, key derivation, key rotation\n"
            "- Transport security: TLS 1.2/1.3, certificate pinning\n"
            "- Random number generation: CSPRNG (untuk tokens, IVs, salts, keys)\n"
            "- Cryptographic protocols: JWT signing/verification, OAuth/OIDC tokens"
            "\n\n"
            "Ancaman dianggap NON-CRYPTO kalau mitigasi utamanya bukan kriptografi:\n"
            "- Denial of Service (mitigasi: rate limiting, capacity planning)\n"
            "- Business logic flaws (mitigasi: input validation, state machines)\n"
            "- Authorization issues (mitigasi: RBAC/ABAC, bukan crypto langsung)\n"
            "- Logging issues (mitigasi: secure logging practices)"
        ),
        
        llm=get_llm_model_string(),
        verbose=verbose,
        allow_delegation=False,
        max_iter=3,
    )
    
    return agent


# ============================================================================
# Task Definition
# ============================================================================

def create_classification_task(threats: list[Threat], agent: Agent) -> Task:
    """
    Buat Task untuk classify batch threats sekaligus.
    """
    
    # Build threats summary untuk task description
    threats_text_lines = []
    for t in threats:
        threats_text_lines.append(
            f"- {t.threat_id} | {t.title} | STRIDE: {t.stride_category.value} | "
            f"CWE: {t.cwe_id or 'N/A'}\n"
            f"  Description: {t.description}\n"
            f"  Affected: {', '.join(t.affected_components) if t.affected_components else 'N/A'}\n"
            f"  Attack Vector: {t.attack_vector or 'N/A'}\n"
        )
    
    threats_text = "\n".join(threats_text_lines)
    
    description = f"""Klasifikasi {len(threats)} ancaman berikut berdasarkan priority dan crypto relevance.

=== ANCAMAN YANG HARUS DIKLASIFIKASIKAN ===

{threats_text}

=== INSTRUKSI ===

Untuk SETIAP ancaman di atas, tentukan:

1. **priority**: Critical / High / Medium / Low
   - Berdasarkan severity, exploitability, dan business impact
   - Critical: bisa langsung menyebabkan compromise besar
   - High: dampak signifikan, memerlukan kondisi tertentu
   - Medium: dampak moderate
   - Low: dampak minimal

2. **is_crypto_related**: true / false
   - true: ancaman bisa dimitigasi dengan kontrol kriptografi
     (encryption, hashing, signing, key management, TLS, CSPRNG, dll.)
   - false: mitigasi utama BUKAN kriptografi
     (DoS prevention, business logic, RBAC, logging, dll.)

3. **rationale**: Alasan singkat (1-2 kalimat) klasifikasi-mu

=== OUTPUT FORMAT ===

Output JSON object yang berisi:
- "classifications": list dengan SETIAP threat_id punya satu entry, berisi:
  - threat_id (string, persis seperti di input)
  - priority (string: "Critical" | "High" | "Medium" | "Low")
  - is_crypto_related (boolean: true | false)
  - rationale (string)

PENTING: Output harus mencakup KEEMPAT field di atas untuk SEMUA {len(threats)} threats.
"""
    
    expected_output = (
        "JSON object yang valid sesuai schema ClassificationOutput, "
        f"berisi list dengan tepat {len(threats)} ClassifiedThreat objects, "
        "masing-masing dengan threat_id, priority, is_crypto_related, dan rationale."
    )
    
    task = Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
        output_pydantic=ClassificationOutput,
    )
    
    return task


# ============================================================================
# High-level API
# ============================================================================

class ThreatClassifier:
    """
    High-level API untuk Threat Classification.
    
    Usage:
        classifier = ThreatClassifier()
        classified_threats = classifier.classify(threats)
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.agent = create_threat_classification_agent(verbose=verbose)
    
    def classify(self, threats: list[Threat]) -> list[Threat]:
        """
        Classify threats — set priority dan is_crypto_related pada setiap threat.
        
        Returns threats dengan field baru ter-populate.
        """
        if not threats:
            return []
        
        task = create_classification_task(threats, self.agent)
        crew = Crew(
            agents=[self.agent],
            tasks=[task],
            process=Process.sequential,
            verbose=self.verbose,
        )
        
        result = crew.kickoff()
        
        # Extract Pydantic output
        if not hasattr(result, "pydantic") or result.pydantic is None:
            raise RuntimeError(
                f"Failed to get structured classification output. "
                f"Raw: {result.raw if hasattr(result, 'raw') else result}"
            )
        
        classification_output: ClassificationOutput = result.pydantic
        
        # Build lookup map
        classification_map: dict[str, ClassifiedThreat] = {
            c.threat_id: c for c in classification_output.classifications
        }
        
        # Merge back ke threats — return NEW list dengan field di-update
        classified_threats = []
        for t in threats:
            classification = classification_map.get(t.threat_id)
            if classification:
                # Create copy of threat dengan classification fields ter-set
                updated = t.model_copy(
                    update={
                        "priority": classification.priority,
                        "is_crypto_related": classification.is_crypto_related,
                        "classification_rationale": classification.rationale,
                    }
                )
                classified_threats.append(updated)
            else:
                # Fallback: kalau classification tidak ada untuk threat ini
                if self.verbose:
                    print(f"  ⚠️  No classification for {t.threat_id}, using default")
                updated = t.model_copy(
                    update={
                        "priority": ThreatPriority.MEDIUM,
                        "is_crypto_related": True,  # Default conservative
                        "classification_rationale": "Default classification (LLM missed this threat)",
                    }
                )
                classified_threats.append(updated)
        
        return classified_threats
    
    def filter_crypto_related(self, threats: list[Threat]) -> list[Threat]:
        """Filter hanya threats yang is_crypto_related=True."""
        return [t for t in threats if t.is_crypto_related is True]
