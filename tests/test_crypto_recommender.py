"""
Test Cryptographic Mitigation Recommender Agent
================================================

Test ringan untuk verifikasi agent bekerja end-to-end pada SATU threat sample.
Lebih cepat dari demo penuh — cocok untuk smoke test.

Usage:
    python -m tests.test_crypto_recommender
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel

from src.agents.crypto_mitigation_recommender import CryptoMitigationRecommender
from src.schemas.crypto_mitigation import MitigationRecommendation
from src.schemas.threat import StrideCategory, Threat

console = Console()


# ============================================================================
# Smoke Test — 1 threat saja, cepat
# ============================================================================

SAMPLE_THREAT = Threat(
    threat_id="TEST-001",
    title="Weak Password Hashing",
    description=(
        "Application stores user passwords using MD5 hash function "
        "without salt. Vulnerable to rainbow table attacks."
    ),
    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
    cwe_id="CWE-916",
    affected_components=["Authentication Service"],
    attack_vector="Offline cracking dengan rainbow tables",
    severity="High",
)


def validate_mitigation(m: MitigationRecommendation) -> dict[str, bool]:
    """Validate bahwa mitigation memenuhi quality criteria."""
    
    checks = {}
    
    # Check 1: Punya minimum 1 algorithm dengan parameter
    checks["has_algorithm_with_params"] = (
        len(m.recommended_algorithms) >= 1
        and any(len(a.parameters) > 0 for a in m.recommended_algorithms)
    )
    
    # Check 2: Punya minimum 1 standard reference (HARUS dari KB)
    checks["has_standard_reference"] = len(m.standard_references) >= 1
    
    # Check 3: Standard reference dari ASVS atau NIST
    valid_standards = ["ASVS", "NIST", "OWASP"]
    checks["references_valid_standards"] = any(
        any(vs in ref.standard.upper() for vs in valid_standards)
        for ref in m.standard_references
    )
    
    # Check 4: Implementation guidance >50 char (cukup detail)
    checks["has_detailed_guidance"] = len(m.implementation_guidance) >= 50
    
    # Check 5: Summary specific (tidak generic)
    generic_phrases = ["apply encryption", "use secure", "implement authentication"]
    summary_lower = m.summary.lower()
    checks["summary_is_specific"] = not any(p in summary_lower for p in generic_phrases)
    
    # Check 6: Algorithm name SPECIFIC (mengandung nama algoritma persis)
    specific_alg_names = [
        "argon2", "bcrypt", "scrypt", "pbkdf2",
        "aes", "chacha20", "rsa", "ecdsa", "ed25519",
        "sha-256", "sha-384", "sha-512", "sha-3",
        "hmac", "gcm", "ccm",
    ]
    alg_text = " ".join(a.name.lower() for a in m.recommended_algorithms)
    checks["algorithm_names_specific"] = any(name in alg_text for name in specific_alg_names)
    
    return checks


def main():
    console.print(Panel.fit(
        "[bold cyan]Phase 2.2 Smoke Test[/bold cyan]\n"
        "[white]Cryptographic Mitigation Recommender Agent[/white]\n"
        "[yellow]Test dengan 1 threat: Weak Password Hashing (CWE-916)[/yellow]",
        border_style="cyan",
    ))
    
    console.print(f"\n[bold]Input Threat:[/bold]")
    console.print(f"  ID: {SAMPLE_THREAT.threat_id}")
    console.print(f"  Title: {SAMPLE_THREAT.title}")
    console.print(f"  CWE: {SAMPLE_THREAT.cwe_id}")
    
    # Run recommender
    console.print(f"\n[bold cyan]🚀 Running agent (verbose mode)...[/bold cyan]\n")
    
    recommender = CryptoMitigationRecommender(verbose=True)
    
    try:
        mitigation = recommender.recommend_for_threat(SAMPLE_THREAT)
    except Exception as e:
        console.print(f"\n[red]❌ Agent failed: {e}[/red]")
        sys.exit(1)
    
    # Display result
    console.print(f"\n[bold green]✅ Mitigation generated:[/bold green]")
    console.print(f"  ID: {mitigation.mitigation_id}")
    console.print(f"  Summary: {mitigation.summary}")
    console.print(f"  Algorithms: {len(mitigation.recommended_algorithms)}")
    console.print(f"  Standard refs: {len(mitigation.standard_references)}")
    console.print(f"  Compliance: {len(mitigation.compliance_mapping)}")
    
    # Quality validation
    console.print(f"\n[bold cyan]🔍 Quality Validation:[/bold cyan]")
    checks = validate_mitigation(mitigation)
    
    for check_name, passed in checks.items():
        emoji = "✅" if passed else "❌"
        color = "green" if passed else "red"
        console.print(f"  {emoji} [{color}]{check_name}[/{color}]")
    
    passed_count = sum(checks.values())
    total = len(checks)
    score_pct = (passed_count / total) * 100
    
    console.print()
    if score_pct >= 80:
        console.print(Panel.fit(
            f"[bold green]✨ TEST PASSED[/bold green]\n"
            f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)\n\n"
            f"[cyan]Ready untuk demo penuh:[/cyan]\n"
            f"  python scripts/run_phase2_demo.py",
            border_style="green",
        ))
    elif score_pct >= 50:
        console.print(Panel.fit(
            f"[bold yellow]⚠️  PARTIAL PASS[/bold yellow]\n"
            f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)\n\n"
            f"[yellow]Beberapa quality criteria belum terpenuhi.[/yellow]\n"
            f"Coba tuning prompt agent atau cek KB content.",
            border_style="yellow",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]❌ TEST FAILED[/bold red]\n"
            f"  Quality score: {passed_count}/{total} ({score_pct:.0f}%)\n",
            border_style="red",
        ))
        sys.exit(1)


if __name__ == "__main__":
    main()
