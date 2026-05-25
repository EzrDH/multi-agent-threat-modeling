"""
Configuration module — memuat environment variables dan setup LLM + Knowledge Base.
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
    print("  2. Edit .env dan isi GEMINI_API_KEY dengan key kamu")
    print("\n  Dapatkan API key gratis di:")
    print("     https://aistudio.google.com/apikey")
    print("=" * 70)
    sys.exit(1)

load_dotenv(ENV_PATH)


# ============================================================================
# LLM Configuration
# ============================================================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))

if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
    print("=" * 70)
    print("⚠️  GEMINI_API_KEY belum diisi di file .env!")
    print("=" * 70)
    print("\nBuka file .env dan isi GEMINI_API_KEY dengan key yang benar.")
    print("Dapatkan API key gratis di: https://aistudio.google.com/apikey")
    print("=" * 70)
    sys.exit(1)

# Set env vars yang dibutuhkan LiteLLM untuk Gemini
os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY
# Clear GOOGLE_API_KEY agar tidak konflik dengan google-genai SDK
# (kalau ter-set, SDK akan prefer GOOGLE_API_KEY over key yang dipass explicit)
if "GOOGLE_API_KEY" in os.environ:
    del os.environ["GOOGLE_API_KEY"]

# ============================================================================
# Phase 2 — Knowledge Base Configuration
# ============================================================================

# Embedding model (Gemini text-embedding-004 - free tier)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "gemini-embedding-2")
EMBEDDING_DIMENSION = 3072  # gemini-embedding-2 default dimension

# Knowledge base paths
KB_ROOT = PROJECT_ROOT / "data" / "knowledge_base"
KB_RAW_DIR = KB_ROOT / "raw"
KB_RAW_ASVS_DIR = KB_RAW_DIR / "asvs"
KB_RAW_NIST_DIR = KB_RAW_DIR / "nist"
KB_CHROMA_DIR = KB_ROOT / "chroma_db"
KB_CHUNKS_FILE = KB_ROOT / "chunks.json"  # Cached parsed chunks

# Buat direktori kalau belum ada
for d in [KB_ROOT, KB_RAW_DIR, KB_RAW_ASVS_DIR, KB_RAW_NIST_DIR]:
    d.mkdir(exist_ok=True, parents=True)

# ChromaDB collection name
CHROMA_COLLECTION_NAME = "crypto_mitigation_kb"

# Retrieval parameters
RETRIEVAL_TOP_K = 5  # Berapa banyak chunk teratas yang di-retrieve per query
RETRIEVAL_MIN_RELEVANCE = 0.5  # Threshold cosine similarity minimum


# ============================================================================
# Logging & Output
# ============================================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(PROJECT_ROOT / "outputs")))
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)


# ============================================================================
# Helper Functions
# ============================================================================

def get_llm_model_string() -> str:
    """Format LiteLLM untuk CrewAI Agent."""
    return f"gemini/{GEMINI_MODEL}"


def print_config_summary():
    """Print konfigurasi yang sedang aktif."""
    print("=" * 70)
    print("🔧 Konfigurasi Multi-Agent Threat Modeling Framework")
    print("=" * 70)
    print(f"  Project Root        : {PROJECT_ROOT}")
    print(f"  LLM Provider        : Google Gemini")
    print(f"  LLM Model           : {GEMINI_MODEL}")
    print(f"  Embedding Model     : {EMBEDDING_MODEL}")
    print(f"  Embedding Dimension : {EMBEDDING_DIMENSION}")
    print(f"  Temperature         : {LLM_TEMPERATURE}")
    print(f"  Knowledge Base Dir  : {KB_ROOT}")
    print(f"  ChromaDB Dir        : {KB_CHROMA_DIR}")
    print(f"  Collection Name     : {CHROMA_COLLECTION_NAME}")
    print(f"  Retrieval Top-K     : {RETRIEVAL_TOP_K}")
    print(f"  API Key             : {GEMINI_API_KEY[:8]}...{GEMINI_API_KEY[-4:]}")
    print("=" * 70)
