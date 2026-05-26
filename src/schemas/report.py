"""
Full Report Schema
==================
Schema untuk output lengkap end-to-end pipeline Phase 2.3:

DFD → Threat ID → Classification → Crypto Mitigation → Full Report

Ini adalah "deliverable utama" framework yang akan jadi bukti diferensiasi
project terhadap framework eksisting.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from src.schemas.crypto_mitigation import MitigationRecommendation
from src.schemas.threat import Threat, ThreatPriority


class PriorityBreakdown(BaseModel):
    """Ringkasan jumlah threat per priority level."""
    
    critical: int = Field(default=0, description="Jumlah threat priority Critical")
    high: int = Field(default=0, description="Jumlah threat priority High")
    medium: int = Field(default=0, description="Jumlah threat priority Medium")
    low: int = Field(default=0, description="Jumlah threat priority Low")
    
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class ComplianceSummary(BaseModel):
    """Aggregated compliance mapping dari seluruh mitigations."""
    
    uu_pdp_articles: list[str] = Field(
        default_factory=list,
        description="Pasal UU PDP No. 27/2022 yang teralamatkan",
    )
    
    pojk_articles: list[str] = Field(
        default_factory=list,
        description="Pasal POJK No. 11/POJK.03/2022 yang teralamatkan",
    )
    
    owasp_top10_categories: list[str] = Field(
        default_factory=list,
        description="Kategori OWASP Top 10 yang teralamatkan",
    )
    
    asvs_controls_referenced: list[str] = Field(
        default_factory=list,
        description="OWASP ASVS V11 controls yang ter-cite di mitigations",
    )
    
    nist_controls_referenced: list[str] = Field(
        default_factory=list,
        description="NIST 800-53 controls yang ter-cite di mitigations",
    )


class PipelineMetadata(BaseModel):
    """Metadata pipeline execution."""
    
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    dfd_name: str = Field(..., description="Nama DFD yang dianalisis")
    framework_version: str = Field(default="2.3", description="Versi framework")
    llm_model: Optional[str] = Field(default=None, description="LLM model yang digunakan")
    embedding_model: Optional[str] = Field(default=None, description="Embedding model")
    total_execution_time_seconds: Optional[float] = Field(default=None)
    agent_call_count: dict = Field(
        default_factory=dict,
        description="Jumlah call per agent (untuk profiling)",
    )


class FullReport(BaseModel):
    """
    Output utama framework Multi-Agent AI Threat Modeling.
    
    Aggregate dari:
    - Threats teridentifikasi (Threat Identification Agent)
    - Classifications (Threat Classification Agent)
    - Crypto mitigations (Cryptographic Mitigation Recommender Agent)
    - Compliance summary (Compliance Mapping aggregation)
    """
    
    # === Section 1: Identitas Report ===
    report_id: str = Field(..., description="ID unik report")
    metadata: PipelineMetadata = Field(..., description="Metadata eksekusi pipeline")
    
    # === Section 2: Threats Teridentifikasi ===
    threats: list[Threat] = Field(
        ...,
        description="Semua threats teridentifikasi (sudah include priority & is_crypto_related)",
    )
    
    threat_count: int = Field(..., description="Total threat teridentifikasi")
    
    priority_breakdown: PriorityBreakdown = Field(
        ...,
        description="Distribusi priority threats",
    )
    
    crypto_related_count: int = Field(
        ...,
        description="Jumlah threats yang kripto-related (akan diproses Crypto Recommender)",
    )
    
    # === Section 3: Mitigations ===
    mitigations: list[MitigationRecommendation] = Field(
        ...,
        description="Crypto mitigation recommendations dari Crypto Recommender",
    )
    
    mitigation_count: int = Field(..., description="Total mitigations dihasilkan")
    
    # === Section 4: Compliance Summary ===
    compliance_summary: ComplianceSummary = Field(
        ...,
        description="Aggregated compliance mapping",
    )
    
    # === Section 5: Quality Metrics ===
    average_confidence_score: Optional[float] = Field(
        default=None,
        description="Rata-rata confidence score dari semua mitigations",
        ge=0.0,
        le=1.0,
    )
    
    coverage_rate: Optional[float] = Field(
        default=None,
        description="Coverage rate: mitigation_count / crypto_related_count",
        ge=0.0,
        le=1.0,
    )


# ============================================================================
# Helper untuk build FullReport dari komponen
# ============================================================================

def build_full_report(
    report_id: str,
    dfd_name: str,
    threats: list[Threat],
    mitigations: list[MitigationRecommendation],
    metadata_extras: Optional[dict] = None,
) -> FullReport:
    """
    Helper untuk build FullReport object dengan auto-calculated aggregates.
    """
    
    # Priority breakdown
    breakdown = PriorityBreakdown()
    for t in threats:
        if t.priority == ThreatPriority.CRITICAL:
            breakdown.critical += 1
        elif t.priority == ThreatPriority.HIGH:
            breakdown.high += 1
        elif t.priority == ThreatPriority.MEDIUM:
            breakdown.medium += 1
        elif t.priority == ThreatPriority.LOW:
            breakdown.low += 1
    
    # Crypto-related count
    crypto_count = sum(1 for t in threats if t.is_crypto_related)
    
    # Aggregate compliance
    compliance = ComplianceSummary()
    asvs_set = set()
    nist_set = set()
    uu_pdp_set = set()
    pojk_set = set()
    owasp_set = set()
    
    for m in mitigations:
        # ASVS & NIST refs
        for ref in m.standard_references:
            std_lower = ref.standard.lower()
            if "asvs" in std_lower:
                asvs_set.add(ref.control_id)
            elif "nist" in std_lower:
                nist_set.add(ref.control_id)
        
        # Compliance mapping
        for cm in m.compliance_mapping:
            reg_lower = cm.regulation.lower()
            section = cm.article_section or ""
            if "uu pdp" in reg_lower or "pdp" in reg_lower:
                uu_pdp_set.add(f"{cm.regulation} {section}".strip())
            elif "pojk" in reg_lower:
                pojk_set.add(f"{cm.regulation} {section}".strip())
            elif "owasp top" in reg_lower:
                owasp_set.add(f"{cm.regulation} {section}".strip())
    
    compliance.uu_pdp_articles = sorted(uu_pdp_set)
    compliance.pojk_articles = sorted(pojk_set)
    compliance.owasp_top10_categories = sorted(owasp_set)
    compliance.asvs_controls_referenced = sorted(asvs_set)
    compliance.nist_controls_referenced = sorted(nist_set)
    
    # Quality metrics
    confidences = [m.confidence_score for m in mitigations if m.confidence_score is not None]
    avg_confidence = sum(confidences) / len(confidences) if confidences else None
    coverage = len(mitigations) / crypto_count if crypto_count > 0 else None
    
    # Metadata
    meta = PipelineMetadata(dfd_name=dfd_name)
    if metadata_extras:
        for k, v in metadata_extras.items():
            if hasattr(meta, k):
                setattr(meta, k, v)
    
    return FullReport(
        report_id=report_id,
        metadata=meta,
        threats=threats,
        threat_count=len(threats),
        priority_breakdown=breakdown,
        crypto_related_count=crypto_count,
        mitigations=mitigations,
        mitigation_count=len(mitigations),
        compliance_summary=compliance,
        average_confidence_score=avg_confidence,
        coverage_rate=coverage,
    )
