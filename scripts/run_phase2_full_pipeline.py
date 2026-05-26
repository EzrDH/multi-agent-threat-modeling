"""
Phase 2.3 Full Pipeline Demo
============================
Demo end-to-end pipeline pada DFD e-commerce login.

Input: 8 threats teridentifikasi (simulasi output Threat ID Agent Phase 1)
   - 5 crypto-related threats (akan dimitigasi)
   - 3 non-crypto threats (akan di-skip dengan rationale)

Output:
- FullReport JSON di outputs/
- Display dengan Rich tables & panels di terminal

Usage:
    python scripts/run_phase2_full_pipeline.py
    python scripts/run_phase2_full_pipeline.py --quiet
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.agents.full_pipeline import FullPipeline
from src.config import OUTPUT_DIR
from src.schemas.report import FullReport
from src.schemas.threat import StrideCategory, Threat

console = Console()


# ============================================================================
# Test Threats — 5 crypto-related + 3 non-crypto untuk demonstrate filtering
# ============================================================================

DEMO_THREATS = [
    # ===== CRYPTO-RELATED (5 threats) =====
    Threat(
        threat_id="THR-001",
        title="Weak Password Hashing",
        description=(
            "User passwords stored using MD5 or unspecified hash function. "
            "Attacker dengan akses ke database dump bisa crack passwords offline."
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
            "Vulnerable terhadap 'alg: none' attack atau algorithm confusion."
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
            "TLS configuration mungkin mengizinkan cipher suite outdated "
            "(RC4, 3DES) atau protocol version lama (TLS 1.0, TLS 1.1)."
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
            "sequential counter. Attacker bisa predict atau brute-force token."
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
            "bukan HTTPS/mTLS. Vulnerable to network sniffing oleh internal attacker."
        ),
        stride_category=StrideCategory.TAMPERING,
        cwe_id="CWE-319",
        affected_components=["Service Mesh", "Internal API"],
        attack_vector="Lateral movement + traffic interception",
        severity="Medium",
    ),
    
    # ===== NON-CRYPTO (3 threats — untuk demonstrate filtering) =====
    Threat(
        threat_id="THR-006",
        title="Login Brute Force Attack",
        description=(
            "Endpoint login tidak memiliki rate limiting atau account lockout. "
            "Attacker bisa coba ribuan password kombinasi dalam waktu singkat."
        ),
        stride_category=StrideCategory.DENIAL_OF_SERVICE,
        cwe_id="CWE-307",
        affected_components=["Authentication Service"],
        attack_vector="Automated password guessing dari multiple IP",
        severity="High",
    ),
    Threat(
        threat_id="THR-007",
        title="Missing Audit Log for Sensitive Operations",
        description=(
            "Operasi sensitif seperti password change, role modification, "
            "dan financial transactions tidak ter-log. Sulit untuk forensics."
        ),
        stride_category=StrideCategory.REPUDIATION,
        cwe_id="CWE-778",
        affected_components=["User Management", "Audit Service"],
        attack_vector="Insider attack tanpa traceability",
        severity="Medium",
    ),
    Threat(
        threat_id="THR-008",
        title="Insecure Direct Object Reference (IDOR)",
        description=(
            "API endpoint menggunakan numeric user ID dari URL tanpa "
            "authorization check. User A bisa akses data user B."
        ),
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        cwe_id="CWE-639",
        affected_components=["User Profile API"],
        attack_vector="URL manipulation",
        severity="High",
    ),
]


# ============================================================================
# Display Functions
# ============================================================================

def display_input_summary(threats: list[Threat]):
    """Tampilkan tabel threats input."""
    table = Table(
        title="📋 Input: Threats Teridentifikasi (Simulasi Phase 1 Output)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Title", style="yellow", width=35)
    table.add_column("STRIDE", width=8)
    table.add_column("CWE", style="magenta", width=10)
    table.add_column("Severity", width=10)
    
    for t in threats:
        table.add_row(
            t.threat_id,
            t.title[:35],
            t.stride_category.value,
            t.cwe_id or "—",
            t.severity or "—",
        )
    
    console.print(table)


def display_classified_threats(report: FullReport):
    """Tampilkan hasil klasifikasi."""
    table = Table(
        title="🏷️  Hasil Klasifikasi (Threat Classification Agent)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Title", width=35)
    table.add_column("Priority", width=10)
    table.add_column("Crypto?", width=8)
    table.add_column("Rationale", width=50)
    
    for t in report.threats:
        priority_color = {
            "Critical": "red",
            "High": "yellow",
            "Medium": "blue",
            "Low": "white",
        }.get(t.priority.value if t.priority else "Medium", "white")
        
        crypto_icon = "✅ YES" if t.is_crypto_related else "❌ NO"
        crypto_color = "green" if t.is_crypto_related else "dim"
        
        rationale = (t.classification_rationale or "")[:50]
        if len(t.classification_rationale or "") > 50:
            rationale += "..."
        
        table.add_row(
            t.threat_id,
            t.title[:35],
            f"[{priority_color}]{t.priority.value if t.priority else '—'}[/{priority_color}]",
            f"[{crypto_color}]{crypto_icon}[/{crypto_color}]",
            rationale,
        )
    
    console.print(table)


def display_priority_breakdown(report: FullReport):
    """Tampilkan breakdown priority."""
    bd = report.priority_breakdown
    console.print(
        f"\n[bold]🎯 Priority Breakdown:[/bold]\n"
        f"  [red]Critical[/red]: {bd.critical}\n"
        f"  [yellow]High[/yellow]:     {bd.high}\n"
        f"  [blue]Medium[/blue]:   {bd.medium}\n"
        f"  [white]Low[/white]:      {bd.low}\n"
        f"  [dim]Total:    {bd.total()}[/dim]"
    )


def display_mitigations_summary(report: FullReport):
    """Tampilkan ringkasan mitigations."""
    if not report.mitigations:
        console.print("\n[yellow]⚠️  Tidak ada mitigations dihasilkan[/yellow]")
        return
    
    table = Table(
        title=f"🔐 Mitigations Generated ({len(report.mitigations)} total)",
        show_header=True,
        header_style="bold green",
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("For Threat", width=8)
    table.add_column("Algorithm(s)", style="yellow", width=30)
    table.add_column("Standards", width=20)
    table.add_column("Compliance", width=20)
    table.add_column("Conf", width=6)
    
    for m in report.mitigations:
        algorithms_str = ", ".join(
            [a.name for a in m.recommended_algorithms[:2]]
        )
        if len(m.recommended_algorithms) > 2:
            algorithms_str += f" (+{len(m.recommended_algorithms) - 2} more)"
        
        standards_str = ", ".join(
            [r.control_id for r in m.standard_references[:3]]
        )
        
        compliance_str = ", ".join(
            list(set(cm.regulation.split()[0] for cm in m.compliance_mapping))[:3]
        )
        
        confidence_str = f"{m.confidence_score:.2f}" if m.confidence_score else "—"
        
        table.add_row(
            m.mitigation_id,
            m.threat_id,
            algorithms_str,
            standards_str,
            compliance_str,
            confidence_str,
        )
    
    console.print(table)


def display_compliance_summary(report: FullReport):
    """Tampilkan ringkasan compliance."""
    cs = report.compliance_summary
    
    console.print("\n[bold]⚖️  Aggregated Compliance Coverage:[/bold]\n")
    
    if cs.asvs_controls_referenced:
        console.print(
            f"  [bold yellow]OWASP ASVS V11 Controls ({len(cs.asvs_controls_referenced)}):[/bold yellow]"
        )
        console.print(f"    {', '.join(cs.asvs_controls_referenced)}")
    
    if cs.nist_controls_referenced:
        console.print(
            f"\n  [bold yellow]NIST 800-53 Controls ({len(cs.nist_controls_referenced)}):[/bold yellow]"
        )
        console.print(f"    {', '.join(cs.nist_controls_referenced)}")
    
    if cs.owasp_top10_categories:
        console.print(
            f"\n  [bold yellow]OWASP Top 10 Categories ({len(cs.owasp_top10_categories)}):[/bold yellow]"
        )
        for cat in cs.owasp_top10_categories:
            console.print(f"    • {cat}")
    
    if cs.uu_pdp_articles:
        console.print(
            f"\n  [bold red]🇮🇩 UU PDP No. 27/2022 ({len(cs.uu_pdp_articles)} pasal):[/bold red]"
        )
        for art in cs.uu_pdp_articles:
            console.print(f"    • {art}")
    
    if cs.pojk_articles:
        console.print(
            f"\n  [bold red]🇮🇩 POJK No. 11/POJK.03/2022 ({len(cs.pojk_articles)} pasal):[/bold red]"
        )
        for art in cs.pojk_articles:
            console.print(f"    • {art}")


def display_final_summary(report: FullReport):
    """Tampilkan final summary panel."""
    avg_conf = report.average_confidence_score or 0.0
    coverage = (report.coverage_rate or 0.0) * 100
    
    conf_color = "green" if avg_conf >= 0.85 else "yellow" if avg_conf >= 0.7 else "red"
    coverage_color = "green" if coverage >= 80 else "yellow" if coverage >= 50 else "red"
    
    console.print(
        Panel.fit(
            f"[bold green]✨ Pipeline Complete[/bold green]\n\n"
            f"  Report ID            : [cyan]{report.report_id}[/cyan]\n"
            f"  DFD                  : {report.metadata.dfd_name}\n"
            f"  LLM Model            : {report.metadata.llm_model}\n"
            f"  Total Threats        : [bold]{report.threat_count}[/bold]\n"
            f"  Crypto-Related       : {report.crypto_related_count}\n"
            f"  Mitigations Generated: [bold]{report.mitigation_count}[/bold]\n"
            f"  Coverage Rate        : [{coverage_color}]{coverage:.1f}%[/{coverage_color}]\n"
            f"  Avg Confidence       : [{conf_color}]{avg_conf:.2f}[/{conf_color}]\n"
            f"  Execution Time       : {report.metadata.total_execution_time_seconds}s\n"
            f"  Agent Calls          : {sum(report.metadata.agent_call_count.values())}",
            border_style="green",
            title="📊 FINAL SUMMARY",
        )
    )


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Phase 2.3 Full Pipeline Demo")
    parser.add_argument("--quiet", action="store_true", help="Minimize verbosity")
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    # Banner
    console.print(
        Panel.fit(
            "[bold cyan]Phase 2.3 — End-to-End Pipeline Demo[/bold cyan]\n"
            "[white]Multi-Agent Threat Modeling Framework[/white]\n\n"
            "[yellow]Pipeline:[/yellow]\n"
            "  DFD → Threat ID → Classification → Crypto Mitigation → Full Report\n\n"
            "[dim]Knowledge Base: OWASP ASVS 5.0 V11 + NIST 800-53 SC/IA[/dim]",
            border_style="cyan",
        )
    )
    
    # Step 0: Show input
    console.print("\n")
    display_input_summary(DEMO_THREATS)
    
    # Run pipeline
    console.print("\n")
    pipeline = FullPipeline(verbose=verbose)
    
    try:
        report = pipeline.run_from_threats(
            DEMO_THREATS,
            dfd_name="ecommerce_login",
        )
    except Exception as e:
        console.print(f"\n[bold red]❌ Pipeline failed: {e}[/bold red]")
        sys.exit(1)
    
    # Display all sections
    console.print("\n")
    display_classified_threats(report)
    display_priority_breakdown(report)
    
    console.print("\n")
    display_mitigations_summary(report)
    
    display_compliance_summary(report)
    
    console.print("\n")
    display_final_summary(report)
    
    # Save to JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"phase2.3_full_report_{timestamp}.json"
    
    with output_path.open("w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))
    
    console.print(f"\n[green]💾 Full report saved to:[/green]\n   [dim]{output_path}[/dim]")


if __name__ == "__main__":
    main()
