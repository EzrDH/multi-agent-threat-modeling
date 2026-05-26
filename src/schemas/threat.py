"""
Threat schema — input ke Cryptographic Mitigation Recommender Agent.

Phase 2.3 UPDATE: Tambah field 'priority' dan 'is_crypto_related' yang
di-set oleh Threat Classification Agent.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class StrideCategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"


class ThreatPriority(str, Enum):
    """Priority level untuk threat (di-classify oleh Threat Classification Agent)."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Threat(BaseModel):
    """
    Representasi satu ancaman teridentifikasi oleh Threat Identification Agent.
    """
    
    threat_id: str = Field(
        ...,
        description="ID unik threat, mis. 'THR-001'",
        examples=["THR-001"],
    )
    
    title: str = Field(
        ...,
        description="Judul singkat ancaman",
        examples=["Weak Password Hashing"],
    )
    
    description: str = Field(
        ...,
        description="Deskripsi detail ancaman dan bagaimana bisa dieksploitasi",
    )
    
    stride_category: StrideCategory = Field(
        ...,
        description="Kategori STRIDE",
    )
    
    cwe_id: Optional[str] = Field(
        default=None,
        description="CWE identifier (Common Weakness Enumeration)",
        examples=["CWE-916"],
    )
    
    affected_components: list[str] = Field(
        default_factory=list,
        description="Komponen dari DFD yang terdampak",
    )
    
    attack_vector: Optional[str] = Field(
        default=None,
        description="Bagaimana attacker bisa exploit ancaman ini",
    )
    
    severity: Optional[str] = Field(
        default=None,
        description="Severity level (legacy field dari Phase 1)",
    )
    
    # === Phase 2.3 — Set oleh Threat Classification Agent ===
    
    priority: Optional[ThreatPriority] = Field(
        default=None,
        description="Priority level di-classify oleh Threat Classification Agent",
    )
    
    is_crypto_related: Optional[bool] = Field(
        default=None,
        description=(
            "True jika threat ini berkaitan dengan kriptografi "
            "(encryption, hashing, signing, key management, TLS, dll.) — "
            "akan diproses oleh Cryptographic Mitigation Recommender Agent."
        ),
    )
    
    classification_rationale: Optional[str] = Field(
        default=None,
        description="Alasan klasifikasi priority dan is_crypto_related",
    )
    
    def to_retrieval_query(self) -> str:
        """Compose query string untuk knowledge base retrieval."""
        parts = [self.title]
        if self.description:
            parts.append(self.description)
        if self.cwe_id:
            parts.append(f"Related to {self.cwe_id}")
        return " ".join(parts)


class ThreatList(BaseModel):
    """Wrapper untuk list of threats."""
    
    threats: list[Threat] = Field(
        ...,
        description="List of identified threats",
    )
    
    metadata: dict = Field(
        default_factory=dict,
        description="Metadata (DFD name, timestamp, etc.)",
    )


class ClassifiedThreat(BaseModel):
    """
    Output structured dari Threat Classification Agent untuk satu threat.
    Field-nya akan di-merge balik ke Threat object.
    """
    
    threat_id: str = Field(..., description="Threat ID untuk reference")
    priority: ThreatPriority = Field(..., description="Priority level")
    is_crypto_related: bool = Field(..., description="Apakah threat ini kripto-related")
    rationale: str = Field(..., description="Alasan singkat klasifikasi")


class ClassificationOutput(BaseModel):
    """Wrapper output untuk batch classification."""
    
    classifications: list[ClassifiedThreat] = Field(
        ...,
        description="List of classified threats",
    )
