"""
Phase 2.2 Demo Script
=====================
Run Cryptographic Mitigation Recommender Agent pada 5 threat dari Phase 1 MVP.

Output:
- Stdout: hasil rekomendasi dengan formatting Rich
- File JSON: outputs/phase2_mitigations_<timestamp>.json

Usage:
    python scripts/run_phase2_demo.py                     # default 5 threats
    python scripts/run_phase2_demo.py --threat THR-001    # satu threat saja
    python scripts/run_phase2_demo.py --quiet             # minimize verbosity
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.agents.crypto_mitigation_recommender import CryptoMitigationRecommender
from src.config import OUTPUT_DIR
from src.schemas.crypto_mitigation import MitigationOutput, MitigationRecommendation
from src.schemas.threat import StrideCategory, Threat

console = Console()


# ============================================================================
# Test Threats — dari Phase 1 MVP output (DFD login e-commerce)
# ============================================================================

DEMO_THREATS = [
    Threat(
        threat_id="THR-001",
        title="Weak Password Hashing",
        description=(
            "User passwords stored using MD5 or unspecified hash function. "
            "Attacker dengan akses ke database dump bisa crack passwords offline "
            "menggunakan rainbow tables atau GPU-accelerated brute force."
        ),
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        cwe_id="CWE-916",
        affected_components=["Authentication Service", "User Database"],
        attack_vector="Offline cracking pada database dump",
        severity="High",
    ),
    Threat(
        threat_id="THR-002",
        title="Insecure JWT Signing",
        description=(
            "JWT signing algorithm tidak ter-validasi secara eksplisit. "
            "Aplikasi rentan terhadap 'alg: none' attack atau algorithm "
            "confusion attack (mis. HS256 dengan public key sebagai secret)."
        ),
        stride_category=StrideCategory.SPOOFING,
        cwe_id="CWE-347",
        affected_components=["Auth Token Service", "API Gateway"],
        attack_vector="Token forgery via algorithm manipulation",
        severity="Critical",
    ),
    Threat(
        threat_id="THR-003",
        title="Weak TLS Configuration",
        description=(
            "TLS configuration mungkin mengizinkan cipher suite yang outdated "
            "(RC4, 3DES, DES) atau protocol version lama (TLS 1.0, TLS 1.1, SSL 3.0). "
            "Vulnerable terhadap downgrade attacks dan POODLE/BEAST."
        ),
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        cwe_id="CWE-327",
        affected_components=["Web Server", "Load Balancer"],
        attack_vector="Network MITM dengan SSL stripping atau downgrade",
        severity="High",
    ),
    Threat(
        threat_id="THR-004",
        title="Predictable Password Reset Token",
        description=(
            "Password reset token generation menggunakan timestamp atau "
            "sequential counter, bukan CSPRNG. Attacker bisa predict atau "
            "brute-force token aktif."
        ),
        stride_category=StrideCategory.SPOOFING,
        cwe_id="CWE-640",
        affected_components=["Password Reset Service"],
        attack_vector="Token prediction atau brute force",
        severity="High",
    ),
    Threat(
        threat_id="THR-005",
        title="Cleartext Internal Communication",
        description=(
            "Komunikasi antar microservices internal menggunakan HTTP plain, "
            "bukan HTTPS/mTLS. Attacker yang berhasil compromise satu service "
            "dalam internal network bisa intercept atau modify komunikasi."
        ),
        stride_category=StrideCategory.TAMPERING,
        cwe_id="CWE-319",
        affected_components=["Service Mesh", "Internal API"],
        attack_vector="Lateral movement + traffic interception",
        severity="Medium",
    ),
]


# ============================================================================
# Display Functions
# ============================================================================

def display_threat_summary(threats: list[Threat]):
    """Tampilkan ringkasan threats yang akan diproses."""
    table = Table(
        title="📋 Threats untuk Diproses Phase 2.2",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Title", style="yellow", width=30)
    table.add_column("STRIDE", width=8)
    table.add_column("CWE", style="magenta", width=10)
    table.add_column("Severity", width=10)
    
    for t in threats:
        table.add_row(
            t.threat_id,
            t.title,
            t.stride_category.value,
            t.cwe_id or "—",
            t.severity or "—",
        )
    
    console.print(table)


def display_mitigation(mitigation: MitigationRecommendation):
    """Tampilkan satu mitigation dengan formatting Rich."""
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]{mitigation.mitigation_id}: {mitigation.threat_title}[/bold cyan]\n"
        f"[white]{mitigation.summary}[/white]",
        border_style="cyan",
    ))
    
    # Recommended Algorithms
    console.print("\n[bold yellow]🔐 Recommended Algorithms:[/bold yellow]")
    for alg in mitigation.recommended_algorithms:
        params_str = ", ".join(f"{k}={v}" for k, v in alg.parameters.items()) or "(no params)"
        console.print(f"  • [bold]{alg.name}[/bold] ({alg.category})")
        console.print(f"    Params: {params_str}")
        if alg.rationale:
            console.print(f"    [dim italic]→ {alg.rationale}[/dim italic]")
        if alg.forbidden_alternatives:
            console.print(f"    [red]❌ Avoid: {', '.join(alg.forbidden_alternatives)}[/red]")
    
    # Standard References
    console.print("\n[bold yellow]📚 Standard References:[/bold yellow]")
    for ref in mitigation.standard_references:
        level_str = f" (Level {ref.level})" if ref.level else ""
        console.print(f"  • [bold]{ref.standard} {ref.control_id}[/bold]{level_str}: {ref.title}")
        if ref.excerpt:
            console.print(f"    [dim italic]\"{ref.excerpt[:120]}...\"[/dim italic]")
    
    # Compliance Mapping
    if mitigation.compliance_mapping:
        console.print("\n[bold yellow]⚖️  Compliance Mapping:[/bold yellow]")
        for cm in mitigation.compliance_mapping:
            article = f" ({cm.article_section})" if cm.article_section else ""
            console.print(f"  • [bold]{cm.regulation}[/bold]{article}: {cm.requirement_summary}")
    
    # Implementation Guidance
    console.print("\n[bold yellow]🛠️  Implementation Guidance:[/bold yellow]")
    console.print(f"  {mitigation.implementation_guidance[:500]}...")
    
    if mitigation.code_example:
        console.print("\n[bold yellow]💻 Code Example:[/bold yellow]")
        console.print(f"[dim]{mitigation.code_example[:300]}...[/dim]")
    
    if mitigation.confidence_score is not None:
        conf_color = "green" if mitigation.confidence_score >= 0.7 else "yellow" if mitigation.confidence_score >= 0.4 else "red"
        console.print(f"\n[bold]Confidence: [{conf_color}]{mitigation.confidence_score:.2f}[/{conf_color}][/bold]")


def save_to_json(mitigations: list[MitigationRecommendation], output_path: Path):
    """Save mitigations ke file JSON."""
    output = MitigationOutput(
        mitigations=mitigations,
        total_threats_analyzed=len(DEMO_THREATS),
        total_recommendations=len(mitigations),
        metadata={
            "timestamp": datetime.now().isoformat(),
            "phase": "2.2",
            "agent": "CryptoMitigationRecommender",
        },
    )
    
    with output_path.open("w", encoding="utf-8") as f:
        # Pydantic v2 model_dump_json
        f.write(output.model_dump_json(indent=2))
    
    console.print(f"\n[green]💾 Saved to {output_path}[/green]")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Phase 2.2 Demo — Crypto Mitigation Recommender")
    parser.add_argument(
        "--threat",
        type=str,
        default=None,
        help="Run untuk satu threat saja (mis. THR-001)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimize agent verbose output",
    )
    args = parser.parse_args()
    
    # Banner
    console.print(Panel.fit(
        "[bold cyan]Phase 2.2 Demo[/bold cyan]\n"
        "[white]Cryptographic Mitigation Recommender Agent[/white]\n\n"
        "[yellow]Knowledge Base: OWASP ASVS 5.0 V11 + NIST 800-53 SC/IA[/yellow]\n"
        "[yellow]LLM: Gemini 2.5 Flash[/yellow]",
        border_style="cyan",
    ))
    
    # Select threats
    if args.threat:
        threats = [t for t in DEMO_THREATS if t.threat_id == args.threat]
        if not threats:
            console.print(f"[red]❌ Threat ID '{args.threat}' tidak ditemukan.[/red]")
            console.print(f"[yellow]Available: {[t.threat_id for t in DEMO_THREATS]}[/yellow]")
            sys.exit(1)
    else:
        threats = DEMO_THREATS
    
    display_threat_summary(threats)
    
    # Run recommender
    console.print(f"\n[bold cyan]🚀 Starting Cryptographic Mitigation Recommender...[/bold cyan]")
    console.print("[dim](Akan butuh ~30-60 detik per threat karena LLM + KB lookup)[/dim]\n")
    
    recommender = CryptoMitigationRecommender(verbose=not args.quiet)
    mitigations = recommender.recommend_for_threats(threats)
    
    # Display results
    console.print(f"\n\n[bold green]{'=' * 70}[/bold green]")
    console.print(f"[bold green]✨ HASIL: {len(mitigations)}/{len(threats)} mitigations berhasil di-generate[/bold green]")
    console.print(f"[bold green]{'=' * 70}[/bold green]")
    
    for m in mitigations:
        display_mitigation(m)
    
    # Save to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"phase2_mitigations_{timestamp}.json"
    save_to_json(mitigations, output_path)
    
    # Final summary
    success_rate = (len(mitigations) / len(threats)) * 100 if threats else 0
    console.print()
    console.print(Panel.fit(
        f"[bold]📊 Final Summary[/bold]\n\n"
        f"  Threats processed   : {len(threats)}\n"
        f"  Mitigations generated: {len(mitigations)}\n"
        f"  Success rate         : {success_rate:.1f}%\n"
        f"  Output file          : {output_path.name}\n\n"
        f"[cyan]Phase 2.2 status: " +
        ("[green]✅ COMPLETE[/green]" if success_rate >= 80 else "[yellow]⚠️  Partial[/yellow]") +
        "[/cyan]",
        border_style="green" if success_rate >= 80 else "yellow",
    ))


if __name__ == "__main__":
    main()
