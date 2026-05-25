"""
Knowledge Base module for Cryptographic Mitigation Recommender Agent.

This module handles:
- Loading raw documents (ASVS markdown, NIST JSON)
- Chunking documents into semantic units
- Embedding chunks via Gemini text-embedding-004
- Storing/retrieving chunks via ChromaDB

Phase 2.1 — Knowledge Base Construction
"""

from .loader import load_asvs_markdown, load_nist_json
from .chunker import chunk_asvs_controls, chunk_nist_controls, Chunk
from .vectorstore import VectorStore
from .retriever import KnowledgeBaseRetriever

__all__ = [
    "load_asvs_markdown",
    "load_nist_json",
    "chunk_asvs_controls",
    "chunk_nist_controls",
    "Chunk",
    "VectorStore",
    "KnowledgeBaseRetriever",
]
