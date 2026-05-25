"""
Pydantic schemas untuk Multi-Agent Threat Modeling Framework.

Mendefinisikan structured input/output untuk:
- Threat (input dari Threat Identification Agent)
- Mitigation (output dari Cryptographic Mitigation Recommender Agent)
"""

from .threat import Threat, ThreatList, StrideCategory
from .crypto_mitigation import (
    StandardReference,
    CryptoAlgorithm,
    ComplianceMapping,
    MitigationRecommendation,
    MitigationOutput,
)

__all__ = [
    "Threat",
    "ThreatList",
    "StrideCategory",
    "StandardReference",
    "CryptoAlgorithm",
    "ComplianceMapping",
    "MitigationRecommendation",
    "MitigationOutput",
]
