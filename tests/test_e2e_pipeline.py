"""
Test E2E Pipeline
=================
Smoke test Phase 2.3 — quick validation dengan 2 threats (1 crypto + 1 non-crypto).
Untuk demo penuh, pakai scripts/run_phase2_full_pipeline.py.

Usage:
    python -m tests.test_e2e_pipeline
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel

from src.agents.full_pipeline import FullPipeline
from src.schemas.threat import StrideCategory, Threat

console = Console()


# Minimum 2 threats: 1 crypto + 1 non-crypto, untuk verify filtering
SAMPLE_THREATS = [
    Threat(
        threat_id="TEST-001",
        title="Weak Password Hashing",
        description=(
            "Application stores user passwords using MD5 hash function without salt."
        ),
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        cwe_id="CWE-916",
        affected_components=["Authentication Service"],
        attack_vector="Rainbow table attack on database dump",
        severity="High",
    ),
    Threat(
        threat_id="TEST-002",
        title="Login Brute Force Attack",
        description=(
            "Endpoint login tidak memiliki rate limiting. "
            "Attacker bisa coba unlimited password attempts."
        ),
        stride_category=StrideCategory.DENIAL_OF_SERVICE,
        cwe_id="CWE-307",
        affected_components=["Authentication Service"],
        attack_vector="Automated brute force",
        severity="High",
    ),
]


def validate_report(report) -> dict[str, bool]:
    """Quality checks."""
    
    checks = {}
    
    # Check 1: Threats classified (priority + is_crypto_related ter-set)
    checks["all_threats_classified"] = all(
        t.priority is not None and t.is_crypto_related is not None
        for t in report.threats
    )
    
    # Check 2: Crypto threat (TEST-001) is_crypto_related=True
    crypto_threat = next((t for t in report.threats if t.threat_id == "TEST-001"), None)
    checks["crypto_threat_classified_correctly"] = (
        crypto_threat is not None and crypto_threat.is_crypto_related is True
    )
    
    # Check 3: Non-crypto threat (TEST-002) is_crypto_related=False
    non_crypto_threat = next((t for t in report.threats if t.threat_id == "TEST-002"), None)
    checks["non_crypto_threat_classified_correctly"] = (
        non_crypto_threat is not None and non_crypto_threat.is_crypto_related is False
    )
    
    # Check 4: Mitigation generated for crypto threat
    checks["mitigation_for_crypto_threat"] = any(
        m.threat_id == "TEST-001" for m in report.mitigations
    )
    
    # Check 5: NO mitigation for non-crypto threat (filtering bekerja)
    checks["no_mitigation_for_non_crypto"] = not any(
        m.threat_id == "TEST-002" for m in report.mitigations
    )
    
    # Check 6: Report ID assigned
    checks["report_id_assigned"] = (
        report.report_id is not None and report.report_id.startswith("RPT-")
    )
    
    # Check 7: Compliance summary populated
    checks["compliance_summary_populated"] = (
        len(report.compliance_summary.asvs_controls_referenced) > 0
        or len(report.compliance_summary.nist_controls_referenced) > 0
    )
    
    return checks


def main():
    console.print(
        Panel.fit(
            "[bold cyan]Phase 2.3 E2E Pipeline Smoke Test[/bold cyan]\n"
            "[yellow]2 threats: 1 crypto + 1 non-crypto (filtering test)[/yellow]",
            border_style="cyan",
        )
    )
    
    console.print(f"\n[bold]Input:[/bold]")
    for t in SAMPLE_THREATS:
        console.print(f"  - {t.threat_id}: {t.title} ({t.cwe_id})")
    
    console.print(f"\n[bold cyan]🚀 Running E2E pipeline...[/bold cyan]\n")
    
    pipeline = FullPipeline(verbose=True)
    
    try:
        report = pipeline.run_from_threats(
            SAMPLE_THREATS,
            dfd_name="smoke_test",
        )
    except Exception as e:
        console.print(f"\n[red]❌ Pipeline failed: {e}[/red]")
        sys.exit(1)
    
    # Display brief result
    console.print(f"\n[bold green]✅ Pipeline completed[/bold green]")
    console.print(f"  Report ID: {report.report_id}")
    console.print(f"  Threats: {report.threat_count}")
    console.print(f"  Crypto-related: {report.crypto_related_count}")
    console.print(f"  Mitigations: {report.mitigation_count}")
    
    # Quality validation
    console.print(f"\n[bold cyan]🔍 Quality Validation:[/bold cyan]")
    checks = validate_report(report)
    
    for check_name, passed in checks.items():
        emoji = "✅" if passed else "❌"
        color = "green" if passed else "red"
        console.print(f"  {emoji} [{color}]{check_name}[/{color}]")
    
    passed_count = sum(checks.values())
    total = len(checks)
    score_pct = (passed_count / total) * 100
    
    console.print()
    
    if score_pct >= 80:
        console.print(
            Panel.fit(
                f"[bold green]✨ TEST PASSED[/bold green]\n"
                f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)\n\n"
                f"[cyan]Ready untuk demo penuh:[/cyan]\n"
                f"  python scripts/run_phase2_full_pipeline.py",
                border_style="green",
            )
        )
    elif score_pct >= 50:
        console.print(
            Panel.fit(
                f"[bold yellow]⚠️  PARTIAL PASS[/bold yellow]\n"
                f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)",
                border_style="yellow",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold red]❌ TEST FAILED[/bold red]\n"
                f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)",
                border_style="red",
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
