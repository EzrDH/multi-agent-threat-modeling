"""
Cryptographic Mitigation schemas — output dari Cryptographic Mitigation Recommender Agent.

Output ini structured agar bisa:
1. Di-validate via Pydantic
2. Di-serialize ke JSON untuk integrasi
3. Di-render sebagai laporan akademik
"""

from typing import Optional

from pydantic import BaseModel, Field


class StandardReference(BaseModel):
    """Reference ke standar (OWASP ASVS atau NIST 800-53)."""
    
    standard: str = Field(
        ...,
        description="Nama standar",
        examples=["OWASP ASVS 5.0", "NIST SP 800-53 Rev.5"],
    )
    
    control_id: str = Field(
        ...,
        description="ID kontrol/requirement",
        examples=["V11.4.2", "IA-5(1)", "SC-13"],
    )
    
    title: str = Field(
        ...,
        description="Judul kontrol/requirement",
        examples=["Password Hashing Functions", "Cryptographic Protection"],
    )
    
    excerpt: Optional[str] = Field(
        default=None,
        description="Kutipan singkat dari standar yang relevan",
    )
    
    level: Optional[str] = Field(
        default=None,
        description="Level ASVS (1/2/3) jika applicable",
    )


class CryptoAlgorithm(BaseModel):
    """Spesifikasi algoritma kriptografi yang direkomendasikan."""
    
    name: str = Field(
        ...,
        description="Nama algoritma",
        examples=["Argon2id", "AES-256-GCM", "RSA-OAEP", "ECDSA P-256"],
    )
    
    category: str = Field(
        ...,
        description="Kategori algoritma",
        examples=["password_hashing", "symmetric_encryption", "asymmetric_encryption",
                  "digital_signature", "key_derivation", "random_number_generation"],
    )
    
    parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Parameter rekomendasi (key=parameter name, value=recommended value)",
        examples=[{"memory_kib": "65536", "iterations": "3", "parallelism": "4"}],
    )
    
    rationale: Optional[str] = Field(
        default=None,
        description="Justifikasi pemilihan algoritma ini",
    )
    
    forbidden_alternatives: list[str] = Field(
        default_factory=list,
        description="Algoritma yang TIDAK boleh dipakai",
        examples=[["MD5", "SHA-1", "plain SHA-256 without KDF"]],
    )


class ComplianceMapping(BaseModel):
    """Mapping ke regulasi/kepatuhan."""
    
    regulation: str = Field(
        ...,
        description="Nama regulasi",
        examples=["UU PDP No. 27/2022", "POJK No. 11/POJK.03/2022", "OWASP Top 10:2021"],
    )
    
    article_section: Optional[str] = Field(
        default=None,
        description="Pasal/section spesifik",
        examples=["Pasal 35", "Pasal 32", "A02:2021"],
    )
    
    requirement_summary: str = Field(
        ...,
        description="Ringkasan apa yang diwajibkan regulasi tersebut",
    )


class MitigationRecommendation(BaseModel):
    """
    Satu rekomendasi mitigasi kriptografi lengkap untuk satu threat.
    
    Ini adalah core output dari Cryptographic Mitigation Recommender Agent —
    representasi terstruktur dari rekomendasi yang spesifik, akurat, dan 
    dapat ditelusuri ke standar.
    """
    
    mitigation_id: str = Field(
        ...,
        description="ID unik mitigasi, mis. 'MIT-001'",
        examples=["MIT-001"],
    )
    
    threat_id: str = Field(
        ...,
        description="ID threat yang dimitigasi (link ke Threat.threat_id)",
        examples=["THR-001"],
    )
    
    threat_title: str = Field(
        ...,
        description="Judul threat (untuk referensi cepat)",
    )
    
    summary: str = Field(
        ...,
        description="Ringkasan rekomendasi mitigasi (1-2 kalimat)",
        examples=["Replace MD5 with Argon2id password hashing using OWASP-recommended parameters"],
    )
    
    recommended_algorithms: list[CryptoAlgorithm] = Field(
        ...,
        description="Algoritma yang direkomendasikan dengan parameter spesifik",
        min_length=1,
    )
    
    standard_references: list[StandardReference] = Field(
        ...,
        description="Referensi ke OWASP ASVS dan/atau NIST 800-53",
        min_length=1,
    )
    
    implementation_guidance: str = Field(
        ...,
        description="Panduan implementasi langkah demi langkah",
    )
    
    compliance_mapping: list[ComplianceMapping] = Field(
        default_factory=list,
        description="Mapping ke regulasi Indonesia (UU PDP, POJK) dan international (OWASP Top 10)",
    )
    
    code_example: Optional[str] = Field(
        default=None,
        description="Contoh code snippet (opsional)",
    )
    
    confidence_score: Optional[float] = Field(
        default=None,
        description="Confidence score 0-1 berdasarkan relevance KB retrieval",
        ge=0.0,
        le=1.0,
    )


class MitigationOutput(BaseModel):
    """Wrapper untuk list mitigations dengan metadata."""
    
    mitigations: list[MitigationRecommendation] = Field(
        ...,
        description="List semua rekomendasi mitigasi",
    )
    
    total_threats_analyzed: int = Field(
        ...,
        description="Total threat yang dianalisis",
    )
    
    total_recommendations: int = Field(
        ...,
        description="Total rekomendasi yang dihasilkan",
    )
    
    metadata: dict = Field(
        default_factory=dict,
        description="Metadata (timestamp, agent version, model, dll.)",
    )
