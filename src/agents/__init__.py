"""
Multi-Agent components untuk Threat Modeling Framework.

Phase 1 MVP — 2 agent dasar:
    - OrchestratorAgent       : koordinator alur kerja
    - ThreatIdentificationAgent : identifikasi threat STRIDE dari DFD

Phase 2 (akan dibangun) :
    - CryptographicMitigationRecommenderAgent ⭐ (komponen diferensiasi)
    - ThreatClassificationAgent
    - ComplianceMappingAgent
"""

from .orchestrator import create_orchestrator_agent
from .threat_identification import create_threat_identification_agent

__all__ = [
    "create_orchestrator_agent",
    "create_threat_identification_agent",
]
