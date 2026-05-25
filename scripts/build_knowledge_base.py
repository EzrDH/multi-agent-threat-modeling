"""
Build Knowledge Base
====================
Script untuk membangun knowledge base ChromaDB dari raw sources:
- OWASP ASVS 5.0 V11 Cryptography (markdown)
- NIST SP 800-53 SC + IA controls (JSON)

Usage:
    python scripts/build_knowledge_base.py            # Build (skip if exists)
    python scripts/build_knowledge_base.py --rebuild  # Force rebuild

Setelah build selesai, jalankan tests/test_kb_retrieval.py untuk verify.
"""

import argparse
import json
import sys
from pathlib import Path

# Tambah project root ke sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel

from src.config import (
    KB_CHUNKS_FILE,
    KB_RAW_ASVS_DIR,
    KB_RAW_NIST_DIR,
    print_config_summary,
)
from src.knowledge_base import (
    VectorStore,
    chunk_asvs_controls,
    chunk_nist_controls,
    load_asvs_markdown,
    load_nist_json,
)

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="Build knowledge base untuk Cryptographic Mitigation Recommender Agent"
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force rebuild collection (hapus existing & start fresh)",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Tampilkan config lalu keluar",
    )
    args = parser.parse_args()

    # Banner
    console.print(Panel.fit(
        "[bold cyan]Knowledge Base Builder[/bold cyan]\n"
        "[white]Phase 2.1 — Multi-Agent Threat Modeling Framework[/white]\n\n"
        "[yellow]Sources: OWASP ASVS 5.0 V11 + NIST 800-53 SC/IA[/yellow]",
        border_style="cyan",
    ))

    if args.show_config:
        print_config_summary()
        return

    # === Step 1: Load ASVS markdown ===
    console.print("\n[bold cyan]📚 Step 1/4: Load ASVS markdown[/bold cyan]")
    asvs_files = list(KB_RAW_ASVS_DIR.glob("*.md"))
    if not asvs_files:
        console.print(f"[red]❌ Tidak ada file .md di {KB_RAW_ASVS_DIR}[/red]")
        console.print("[yellow]   Pastikan ASVS_5.0_V11_Cryptography.md sudah ada di folder tersebut[/yellow]")
        sys.exit(1)

    all_asvs_chunks = []
    for asvs_file in asvs_files:
        console.print(f"  [dim]Loading {asvs_file.name}...[/dim]")
        asvs_data = load_asvs_markdown(asvs_file)
        chunks = chunk_asvs_controls(asvs_data)
        all_asvs_chunks.extend(chunks)
        console.print(
            f"  [green]✅ {asvs_file.name}: {len(asvs_data.get('sections', []))} sections, "
            f"{len(chunks)} requirements → chunks[/green]"
        )

    # === Step 2: Load NIST JSON ===
    console.print("\n[bold cyan]📚 Step 2/4: Load NIST 800-53 JSON[/bold cyan]")
    nist_files = list(KB_RAW_NIST_DIR.glob("*.json"))
    if not nist_files:
        console.print(f"[red]❌ Tidak ada file .json di {KB_RAW_NIST_DIR}[/red]")
        sys.exit(1)

    all_nist_chunks = []
    for nist_file in nist_files:
        console.print(f"  [dim]Loading {nist_file.name}...[/dim]")
        nist_data = load_nist_json(nist_file)
        chunks = chunk_nist_controls(nist_data)
        all_nist_chunks.extend(chunks)
        console.print(
            f"  [green]✅ {nist_file.name}: {len(chunks)} controls → chunks[/green]"
        )

    # === Step 3: Save chunks cache ===
    console.print("\n[bold cyan]💾 Step 3/4: Cache chunks ke JSON[/bold cyan]")
    all_chunks = all_asvs_chunks + all_nist_chunks
    KB_CHUNKS_FILE.parent.mkdir(exist_ok=True, parents=True)
    with KB_CHUNKS_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            [c.to_dict() for c in all_chunks],
            f,
            ensure_ascii=False,
            indent=2,
        )
    console.print(f"  [green]✅ {len(all_chunks)} chunks saved to {KB_CHUNKS_FILE}[/green]")

    # === Step 4: Embed + Store di ChromaDB ===
    console.print("\n[bold cyan]🧠 Step 4/4: Embed chunks via Gemini & store di ChromaDB[/bold cyan]")
    console.print("[dim]   (akan butuh beberapa menit karena rate limit Gemini free tier)[/dim]\n")

    vs = VectorStore()
    count = vs.populate(all_chunks, rebuild=args.rebuild)

    # === Summary ===
    stats = vs.stats()
    console.print("\n")
    console.print(Panel.fit(
        f"[bold green]✨ Knowledge Base Build COMPLETE![/bold green]\n\n"
        f"  ASVS chunks    : {len(all_asvs_chunks)}\n"
        f"  NIST chunks    : {len(all_nist_chunks)}\n"
        f"  Total chunks   : {count}\n"
        f"  Collection     : {stats['collection_name']}\n"
        f"  Persist dir    : {stats['persist_dir']}\n"
        f"  Embedding model: {stats['embedding_model']}\n\n"
        f"[cyan]Next step: python -m tests.test_kb_retrieval[/cyan]",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
