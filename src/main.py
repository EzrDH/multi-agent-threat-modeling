"""
Main Entry Point
================
Menjalankan alur Multi-Agent Threat Modeling Framework Phase 1 MVP.

Penggunaan:
    python -m src.main                              # Pakai DFD default (ecommerce_login.md)
    python -m src.main --dfd path/to/your_dfd.md    # Pakai DFD custom
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from crewai import Crew, Process, Task
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.agents import (
    create_orchestrator_agent,
    create_threat_identification_agent,
)
from src.agents.threat_identification import THREAT_IDENTIFICATION_TASK_PROMPT
from src.config import OUTPUT_DIR, PROJECT_ROOT, print_config_summary

console = Console()


# ============================================================================
# Helper Functions
# ============================================================================

def load_dfd(dfd_path: Path) -> str:
    """Memuat konten DFD dari file."""
    if not dfd_path.exists():
        console.print(f"[red]❌ File DFD tidak ditemukan: {dfd_path}[/red]")
        sys.exit(1)

    return dfd_path.read_text(encoding="utf-8")


def extract_json_from_output(text: str) -> dict | None:
    """
    Mengekstrak JSON dari output LLM yang biasanya
    dibungkus dalam markdown code block ```json ... ```
    """
    # Coba cari pattern ```json ... ```
    json_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if json_match:
        json_str = json_match.group(1)
    else:
        # Coba cari pattern ``` ... ``` (tanpa label json)
        code_match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
        if code_match:
            json_str = code_match.group(1)
        else:
            # Coba parse seluruh teks sebagai JSON
            json_str = text.strip()

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        console.print(f"[yellow]⚠️  Gagal parse JSON: {e}[/yellow]")
        console.print(f"[dim]Raw output snippet: {json_str[:200]}...[/dim]")
        return None


def save_results(result_data: dict, dfd_filename: str) -> Path:
    """Menyimpan hasil ke direktori outputs/."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"threat_model_{dfd_filename}_{timestamp}.json"
    output_file.write_text(
        json.dumps(result_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_file


def display_results(threats_data: dict):
    """Menampilkan hasil threat modeling dengan format yang rapi."""
    if not threats_data:
        console.print("[yellow]⚠️  Tidak ada data threat untuk ditampilkan.[/yellow]")
        return

    # Header
    system_name = threats_data.get("system_name", "Unknown System")
    total = threats_data.get("total_threats_identified", 0)
    console.print(
        Panel.fit(
            f"[bold cyan]Threat Model untuk: {system_name}[/bold cyan]\n"
            f"Total ancaman teridentifikasi: [bold green]{total}[/bold green]",
            border_style="cyan",
        )
    )

    # Tabel threats
    threats = threats_data.get("threats", [])
    if threats:
        table = Table(title="Daftar Ancaman STRIDE", show_lines=True)
        table.add_column("ID", style="cyan", width=6)
        table.add_column("Kategori", style="magenta", width=20)
        table.add_column("Judul", style="white", width=35)
        table.add_column("Lokasi", style="yellow", width=25)
        table.add_column("Severity", style="red", width=10)

        severity_style = {
            "Critical": "[bold red]Critical[/bold red]",
            "High": "[red]High[/red]",
            "Medium": "[yellow]Medium[/yellow]",
            "Low": "[green]Low[/green]",
        }

        for threat in threats:
            table.add_row(
                threat.get("id", "-"),
                threat.get("category", "-"),
                threat.get("title", "-"),
                threat.get("location", "-"),
                severity_style.get(threat.get("severity", "-"), threat.get("severity", "-")),
            )

        console.print(table)

    # Summary
    summary = threats_data.get("summary", {})
    if summary:
        console.print("\n[bold]📊 Ringkasan:[/bold]")
        by_category = summary.get("by_category", {})
        if by_category:
            console.print("  [bold]Per Kategori STRIDE:[/bold]")
            for category, count in by_category.items():
                console.print(f"    • {category}: {count}")

        by_severity = summary.get("by_severity", {})
        if by_severity:
            console.print("  [bold]Per Severity:[/bold]")
            for severity, count in by_severity.items():
                console.print(f"    • {severity}: {count}")


# ============================================================================
# Main Flow
# ============================================================================

def run_threat_modeling(dfd_path: Path) -> dict | None:
    """
    Menjalankan alur multi-agent threat modeling pada DFD yang diberikan.

    Phase 1 MVP: hanya 2 agent (Orchestrator + Threat Identification).
    Phase 2+ : akan tambah Cryptographic Mitigation Recommender, dll.
    """
    console.print("\n[bold cyan]🚀 Memulai analisis threat modeling...[/bold cyan]\n")

    # === 1. Load DFD ===
    dfd_content = load_dfd(dfd_path)
    console.print(f"[green]✅ DFD dimuat dari: {dfd_path.name}[/green]")
    console.print(f"[dim]Panjang konten: {len(dfd_content)} karakter[/dim]\n")

    # === 2. Inisialisasi Agents ===
    console.print("[cyan]🤖 Menginisialisasi agents...[/cyan]")
    orchestrator = create_orchestrator_agent()
    threat_identifier = create_threat_identification_agent()
    console.print("[green]✅ 2 agents siap (Orchestrator + Threat Identification)[/green]\n")

    # === 3. Definisikan Task ===
    threat_identification_task = Task(
        description=THREAT_IDENTIFICATION_TASK_PROMPT.format(dfd_content=dfd_content),
        expected_output=(
            "JSON terstruktur berisi daftar threat STRIDE dengan field: "
            "id, category, title, description, location, cwe_reference, severity, "
            "rationale. Dibungkus dalam markdown code block ```json ... ```."
        ),
        agent=threat_identifier,
    )

    # === 4. Bangun Crew ===
    crew = Crew(
        agents=[orchestrator, threat_identifier],
        tasks=[threat_identification_task],
        process=Process.sequential,
        verbose=True,
    )

    # === 5. Jalankan ===
    console.print("[cyan]⚙️  Menjalankan crew workflow...[/cyan]")
    console.print("[dim](ini akan memakan waktu 30-60 detik tergantung Gemini API)[/dim]\n")

    try:
        result = crew.kickoff()
    except Exception as e:
        console.print(f"\n[red]❌ Error saat menjalankan crew: {e}[/red]")
        return None

    # === 6. Parse hasil ===
    raw_output = str(result)
    threats_data = extract_json_from_output(raw_output)

    if threats_data is None:
        console.print("\n[yellow]⚠️  Hasil mentah (gagal parse JSON):[/yellow]")
        console.print(Panel(raw_output[:2000], border_style="yellow"))
        return None

    return threats_data


# ============================================================================
# CLI
# ============================================================================

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Multi-Agent AI Framework untuk Threat Modeling (Phase 1 MVP)"
    )
    parser.add_argument(
        "--dfd",
        type=str,
        default=None,
        help="Path ke file DFD (default: data/test_dfds/ecommerce_login.md)",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Tampilkan konfigurasi lalu keluar",
    )
    args = parser.parse_args()

    # === Banner ===
    console.print(
        Panel.fit(
            "[bold cyan]Multi-Agent AI Framework[/bold cyan]\n"
            "[white]for Automated Threat Modeling on Design SSDLC[/white]\n\n"
            "[yellow]Phase 1 MVP — D4 Rekayasa Kriptografi, Poltek SSN[/yellow]",
            border_style="cyan",
        )
    )

    if args.show_config:
        print_config_summary()
        return

    # === Tentukan DFD path ===
    if args.dfd:
        dfd_path = Path(args.dfd)
    else:
        dfd_path = PROJECT_ROOT / "data" / "test_dfds" / "ecommerce_login.md"

    # === Jalankan threat modeling ===
    threats_data = run_threat_modeling(dfd_path)

    if threats_data is None:
        console.print("\n[red]❌ Gagal mendapatkan hasil yang dapat diparse.[/red]")
        sys.exit(1)

    # === Tampilkan hasil ===
    console.print("\n")
    display_results(threats_data)

    # === Simpan hasil ===
    dfd_filename = dfd_path.stem
    output_file = save_results(threats_data, dfd_filename)
    console.print(f"\n[green]💾 Hasil disimpan ke: {output_file}[/green]")
    console.print("\n[bold green]✨ Selesai![/bold green]\n")


if __name__ == "__main__":
    main()
