"""
Test Knowledge Base Retrieval
=============================
Verifikasi retrieval bekerja untuk threat-threat dari Phase 1 MVP output.

Usage:
    python -m tests.test_kb_retrieval
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.knowledge_base import KnowledgeBaseRetriever

console = Console()


# Test cases berdasarkan threat yang ditemukan Phase 1 MVP pada DFD e-commerce login
TEST_THREATS = [
    {
        "title": "Weak Password Hashing Algorithm",
        "description": "System uses MD5 or unspecified hash function for password storage",
        "cwe": "CWE-916",
        "expected_keywords": ["Argon2", "bcrypt", "PBKDF2", "IA-5", "V11.4.2"],
    },
    {
        "title": "Insecure JWT Signing",
        "description": "JWT signing algorithm not specified, may accept alg:none",
        "cwe": "CWE-347",
        "expected_keywords": ["RS256", "ES256", "alg: none", "V11.8", "JWT"],
    },
    {
        "title": "Weak TLS Configuration",
        "description": "TLS configuration may allow outdated cipher suites or protocols",
        "cwe": "CWE-327",
        "expected_keywords": ["TLS 1.3", "AEAD", "SC-8", "V11.7"],
    },
    {
        "title": "Predictable Password Reset Token",
        "description": "Password reset token generation may be predictable",
        "cwe": "CWE-640",
        "expected_keywords": ["CSPRNG", "entropy", "V11.5", "SC-23"],
    },
    {
        "title": "Cleartext Internal Communication",
        "description": "Internal HTTP communication may not be encrypted",
        "cwe": "CWE-319",
        "expected_keywords": ["TLS", "SC-8", "V11.7"],
    },
]


def evaluate_relevance(content: str, expected_keywords: list[str]) -> tuple[int, list[str]]:
    """Cek berapa expected keyword yang muncul di content."""
    matched = [kw for kw in expected_keywords if kw.lower() in content.lower()]
    return len(matched), matched


def main():
    console.print(Panel.fit(
        "[bold cyan]Knowledge Base Retrieval Test[/bold cyan]\n"
        "[white]Verify retrieval untuk 5 threat dari Phase 1 MVP[/white]",
        border_style="cyan",
    ))

    retriever = KnowledgeBaseRetriever()

    # Check KB initialized
    stats = retriever.stats()
    console.print(f"\n[dim]Collection: {stats['collection_name']}[/dim]")
    console.print(f"[dim]Total chunks: {stats['total_chunks']}[/dim]")

    if stats["total_chunks"] == 0:
        console.print(
            "[red]❌ Knowledge base kosong! Jalankan dulu:[/red]\n"
            "   [yellow]python scripts/build_knowledge_base.py[/yellow]"
        )
        sys.exit(1)

    # Run test cases
    total_score = 0
    max_score = 0

    for i, threat in enumerate(TEST_THREATS, 1):
        console.print(f"\n[bold cyan]━━━ Test {i}/{len(TEST_THREATS)}: {threat['title']} ({threat['cwe']}) ━━━[/bold cyan]")
        console.print(f"[dim]Description: {threat['description']}[/dim]")

        # Retrieve
        results = retriever.retrieve_for_threat(
            threat_title=threat["title"],
            threat_description=threat["description"],
            cwe_id=threat["cwe"],
            top_k=5,
        )

        if not results:
            console.print("[red]  ❌ No results retrieved[/red]")
            continue

        # Display table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Rank", style="cyan", width=4)
        table.add_column("Source", width=8)
        table.add_column("Chunk ID", style="yellow", width=18)
        table.add_column("Similarity", justify="right", width=10)
        table.add_column("Preview", width=60)

        for rank, r in enumerate(results, 1):
            preview = r["content"][:80].replace("\n", " ") + "..."
            sim = f"{r['similarity']:.3f}" if r.get("similarity") else "N/A"
            source = r["metadata"].get("source", "")
            table.add_row(str(rank), source[:6], r["chunk_id"], sim, preview)

        console.print(table)

        # Evaluate
        all_content = " ".join([r["content"] for r in results])
        matched_count, matched_kw = evaluate_relevance(all_content, threat["expected_keywords"])
        max_score += len(threat["expected_keywords"])
        total_score += matched_count

        if matched_count == len(threat["expected_keywords"]):
            status = "[green]✅ EXCELLENT[/green]"
        elif matched_count >= len(threat["expected_keywords"]) * 0.6:
            status = "[yellow]⚠️  GOOD[/yellow]"
        else:
            status = "[red]❌ POOR[/red]"

        console.print(
            f"\n  Expected keywords: {threat['expected_keywords']}\n"
            f"  Matched ({matched_count}/{len(threat['expected_keywords'])}): {matched_kw}\n"
            f"  Status: {status}"
        )

    # Final summary
    overall_pct = (total_score / max_score) * 100 if max_score else 0
    console.print("\n")
    console.print(Panel.fit(
        f"[bold]📊 Final Score[/bold]\n\n"
        f"  Total matched : {total_score}/{max_score} keywords\n"
        f"  Accuracy      : {overall_pct:.1f}%\n\n"
        f"  Phase 2.1 status: " + (
            "[green]✅ READY for Phase 2.2[/green]" if overall_pct >= 60
            else "[yellow]⚠️  KB perlu enrichment[/yellow]"
        ),
        border_style="green" if overall_pct >= 60 else "yellow",
    ))


if __name__ == "__main__":
    main()
