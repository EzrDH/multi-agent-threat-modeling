"""
Configuration module — memuat environment variables dan setup LLM.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Muat .env dari root project
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"

if not ENV_PATH.exists():
    print("=" * 70)
    print("⚠️  File .env tidak ditemukan!")
    print("=" * 70)
    print("\nSilakan:")
    print("  1. Salin .env.example menjadi .env")
    print("     cp .env.example .env  (Linux/Mac)")
    print("     copy .env.example .env  (Windows)")
    print("\n  2. Edit .env dan isi GEMINI_API_KEY dengan key kamu")
    print("\n  3. Dapatkan API key gratis di:")
    print("     https://aistudio.google.com/apikey")
    print("=" * 70)
    sys.exit(1)

load_dotenv(ENV_PATH)


# === Konfigurasi LLM ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))

# === Validasi API Key ===
if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
    print("=" * 70)
    print("⚠️  GEMINI_API_KEY belum diisi di file .env!")
    print("=" * 70)
    print("\nBuka file .env dan ganti baris:")
    print("  GEMINI_API_KEY=your_gemini_api_key_here")
    print("\nMenjadi:")
    print("  GEMINI_API_KEY=AIza... (key kamu yang sebenarnya)")
    print("\nDapatkan API key gratis di: https://aistudio.google.com/apikey")
    print("=" * 70)
    sys.exit(1)


# === Konfigurasi Logging ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


# === Output Directory ===
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./outputs"))
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)


# === LiteLLM Configuration (dipakai oleh CrewAI) ===
# CrewAI menggunakan LiteLLM untuk berkomunikasi dengan LLM
# Set env vars yang dibutuhkan LiteLLM untuk Gemini
os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY


def get_llm_model_string() -> str:
    """
    Mengembalikan string model dalam format LiteLLM
    untuk dipakai oleh CrewAI Agent.

    Format: 'provider/model-name'
    Contoh: 'gemini/gemini-2.5-flash'
    """
    return f"gemini/{GEMINI_MODEL}"


def print_config_summary():
    """Print konfigurasi yang sedang aktif (untuk debugging)."""
    print("=" * 70)
    print("🔧 Konfigurasi Multi-Agent Threat Modeling Framework")
    print("=" * 70)
    print(f"  Project Root  : {PROJECT_ROOT}")
    print(f"  LLM Provider  : Google Gemini")
    print(f"  Model         : {GEMINI_MODEL}")
    print(f"  Temperature   : {LLM_TEMPERATURE}")
    print(f"  Output Dir    : {OUTPUT_DIR}")
    print(f"  API Key       : {GEMINI_API_KEY[:8]}...{GEMINI_API_KEY[-4:]}")
    print("=" * 70)
