"""
Phase 2.3 End-to-End Pipeline
=============================
Full multi-agent threat modeling pipeline:

    DFD Input
      │
      ▼ [Threat Identification Agent — Phase 1]
      Threats teridentifikasi (10x STRIDE threats)
      │
      ▼ [Threat Classification Agent — Phase 2.3]
      Threats dengan priority + is_crypto_related
      │
      ▼ [Filter: is_crypto_related == True]
      Crypto-related threats only
      │
      ▼ [Cryptographic Mitigation Recommender Agent — Phase 2.2]
      Specific mitigations dengan ASVS/NIST + compliance
      │
      ▼ [Aggregate]
      FullReport JSON

Usage:
    python scripts/run_phase2_full_pipeline.py [--dfd DFD_PATH] [--quiet]
"""

import sys
import time
import uuid
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console

from src.agents.threat_classification import ThreatClassifier
from src.agents.crypto_mitigation_recommender import CryptoMitigationRecommender
from src.config import EMBEDDING_MODEL, GEMINI_MODEL
from src.schemas.crypto_mitigation import MitigationRecommendation
from src.schemas.report import FullReport, build_full_report
from src.schemas.threat import Threat


console = Console()


class FullPipeline:
    """
    Phase 2.3 End-to-End Pipeline.
    
    Saat ini menerima threats sebagai input (sudah ter-identifikasi dari Phase 1).
    Untuk full E2E dengan DFD parsing, gunakan `run_from_dfd()` (yang akan 
    invoke Phase 1 Threat Identification Agent dulu).
    
    Usage:
        pipeline = FullPipeline(verbose=True)
        report = pipeline.run_from_threats(threats, dfd_name="my_system")
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._classifier: Optional[ThreatClassifier] = None
        self._recommender: Optional[CryptoMitigationRecommender] = None
        
        # Track agent calls untuk profiling
        self.agent_call_count = {
            "threat_classification": 0,
            "crypto_mitigation_recommender": 0,
        }
    
    @property
    def classifier(self) -> ThreatClassifier:
        if self._classifier is None:
            self._classifier = ThreatClassifier(verbose=self.verbose)
        return self._classifier
    
    @property
    def recommender(self) -> CryptoMitigationRecommender:
        if self._recommender is None:
            self._recommender = CryptoMitigationRecommender(verbose=self.verbose)
        return self._recommender
    
    def run_from_threats(
        self,
        threats: list[Threat],
        dfd_name: str = "unknown",
    ) -> FullReport:
        """
        Run pipeline mulai dari list threats (skip Phase 1 Threat ID Agent).
        
        Cocok untuk:
        - Testing dengan threats yang sudah pre-defined
        - Re-process threats dari Phase 1 output JSON
        """
        start_time = time.time()
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        
        if self.verbose:
            console.print(f"\n[bold cyan]🚀 Pipeline Started — Report ID: {report_id}[/bold cyan]")
            console.print(f"[dim]DFD: {dfd_name} | Input threats: {len(threats)}[/dim]\n")
        
        # ====================================================================
        # Step 1: Threat Classification
        # ====================================================================
        if self.verbose:
            console.print("[bold]━━ Step 1/3: Threat Classification ━━[/bold]")
        
        classified_threats = self.classifier.classify(threats)
        self.agent_call_count["threat_classification"] += 1
        
        # Hitung crypto-related
        crypto_threats = self.classifier.filter_crypto_related(classified_threats)
        non_crypto_count = len(classified_threats) - len(crypto_threats)
        
        if self.verbose:
            console.print(
                f"  ✅ Classified {len(classified_threats)} threats: "
                f"[bold yellow]{len(crypto_threats)} crypto-related[/bold yellow], "
                f"{non_crypto_count} non-crypto"
            )
        
        # ====================================================================
        # Step 2: Crypto Mitigation Recommendation (hanya untuk crypto-related)
        # ====================================================================
        if self.verbose:
            console.print(f"\n[bold]━━ Step 2/3: Crypto Mitigation Recommender ━━[/bold]")
            console.print(f"  [dim]Processing {len(crypto_threats)} crypto-related threats...[/dim]")
        
        mitigations: list[MitigationRecommendation] = []
        
        if crypto_threats:
            mitigations = self.recommender.recommend_for_threats(crypto_threats)
            self.agent_call_count["crypto_mitigation_recommender"] += len(crypto_threats)
            
            if self.verbose:
                console.print(
                    f"  ✅ Generated {len(mitigations)}/{len(crypto_threats)} "
                    f"crypto mitigations"
                )
        else:
            if self.verbose:
                console.print("  [yellow]⚠️  No crypto-related threats to mitigate[/yellow]")
        
        # ====================================================================
        # Step 3: Aggregate ke FullReport
        # ====================================================================
        if self.verbose:
            console.print(f"\n[bold]━━ Step 3/3: Aggregate Report ━━[/bold]")
        
        elapsed = time.time() - start_time
        
        report = build_full_report(
            report_id=report_id,
            dfd_name=dfd_name,
            threats=classified_threats,
            mitigations=mitigations,
            metadata_extras={
                "llm_model": GEMINI_MODEL,
                "embedding_model": EMBEDDING_MODEL,
                "total_execution_time_seconds": round(elapsed, 2),
                "agent_call_count": self.agent_call_count.copy(),
            },
        )
        
        if self.verbose:
            console.print(f"  ✅ Report assembled in {elapsed:.1f}s")
            console.print(f"\n[bold green]🎯 Pipeline Complete — Report ID: {report_id}[/bold green]")
        
        return report
    
    def reset_call_count(self):
        """Reset agent call counter untuk run baru."""
        self.agent_call_count = {
            "threat_classification": 0,
            "crypto_mitigation_recommender": 0,
        }
