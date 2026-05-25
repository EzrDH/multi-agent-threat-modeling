"""
Threat schema — input ke Cryptographic Mitigation Recommender Agent.

Match dengan output Phase 1 MVP Threat Identification Agent.
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


class Threat(BaseModel):
    """
    Representasi satu ancaman teridentifikasi oleh Threat Identification Agent.
    
    Format ini match dengan output JSON Phase 1 MVP.
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
        examples=["Application uses MD5 to hash user passwords, vulnerable to rainbow table attacks"],
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
        examples=[["Authentication Service", "User Database"]],
    )
    
    attack_vector: Optional[str] = Field(
        default=None,
        description="Bagaimana attacker bisa exploit ancaman ini",
        examples=["Attacker dengan akses ke database dump bisa crack password offline"],
    )
    
    severity: Optional[str] = Field(
        default=None,
        description="Severity level (Critical/High/Medium/Low)",
        examples=["High"],
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
        description="Metadata sources (DFD nama, timestamp, etc.)",
    )
