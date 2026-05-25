"""
Vector Store (ChromaDB)
=======================
Mengelola persistence chunks di ChromaDB dengan embedding via Gemini
text-embedding-004.

Workflow:
    vs = VectorStore()
    vs.populate(chunks)   # build/rebuild collection
    results = vs.query("weak password hashing", top_k=5)
"""

import time
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings
from chromadb.utils.embedding_functions import EmbeddingFunction

# Import library SDK baru dari Google
from google import genai
from google.genai import types
from google.genai import errors

from src.config import (
    CHROMA_COLLECTION_NAME,
    EMBEDDING_MODEL,
    GEMINI_API_KEY,
    KB_CHROMA_DIR,
    RETRIEVAL_TOP_K,
)
from src.knowledge_base.chunker import Chunk


# ============================================================================
# Custom Embedding Function — Gemini text-embedding-004
# ============================================================================

class GeminiEmbeddingFunction(EmbeddingFunction):
    """Wrap Google Generative AI Embeddings ke format ChromaDB."""

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        self.model_name = model_name
        # Inisialisasi client baru dengan API key
        self.client = genai.Client(api_key=GEMINI_API_KEY)

    def __call__(self, input: list[str]) -> list[list[float]]:
        """Embed batch of texts."""
        embeddings = []
        for text in input:
            # Retry on rate limit
            for attempt in range(3):
                try:
                    result = self.client.models.embed_content(
                        model=self.model_name,
                        contents=text,
                        config=types.EmbedContentConfig(
                            task_type="RETRIEVAL_DOCUMENT"
                        )
                    )
                    embeddings.append(result.embeddings[0].values)
                    break
                except errors.ClientError as e:
                    if e.code == 429:
                        # rate limit
                        time.sleep(5)
                    elif e.code == 404:
                        # model not found
                        time.sleep(5)
                    else:
                        raise RuntimeError(f"Google API Error: {e}")
                except Exception as e:
                    raise RuntimeError(f"Unexpected error: {e}")
        return embeddings

# ============================================================================
# VectorStore class
# ============================================================================

class VectorStore:
    """High-level wrapper untuk ChromaDB."""

    def __init__(
        self,
        persist_dir: Path = KB_CHROMA_DIR,
        collection_name: str = CHROMA_COLLECTION_NAME,
    ):
        self.persist_dir = persist_dir
        self.collection_name = collection_name

        # ChromaDB persistent client
        self.client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=Settings(anonymized_telemetry=False),
        )

        self.embedding_function = GeminiEmbeddingFunction()
        self._collection = None

    @property
    def collection(self):
        """Lazy-load atau create collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_function,
                metadata={
                    "hnsw:space": "cosine",
                    "description": "Crypto mitigation knowledge base (ASVS V11 + NIST 800-53 SC/IA)",
                },
            )
        return self._collection

    def populate(self, chunks: list[Chunk], rebuild: bool = False) -> int:
        """
        Populate collection dengan chunks.

        Args:
            chunks: list of Chunk objects
            rebuild: kalau True, hapus collection existing & rebuild from scratch

        Returns:
            Jumlah chunks yang ter-add
        """
        if rebuild:
            try:
                self.client.delete_collection(name=self.collection_name)
                print(f"  🗑️  Deleted existing collection '{self.collection_name}'")
            except Exception:
                pass
            self._collection = None  # Reset lazy property

        col = self.collection

        # Prepare batch data
        ids = [chunk.chunk_id for chunk in chunks]
        documents = [chunk.content for chunk in chunks]
        # ChromaDB metadata harus berisi tipe primitif (str, int, float, bool)
        metadatas = [
            {k: (v if isinstance(v, (str, int, float, bool)) else str(v))
             for k, v in chunk.metadata.items()}
            for chunk in chunks
        ]

        # Add dalam batches kecil untuk hindari rate limit Gemini
        BATCH_SIZE = 10
        added = 0
        for i in range(0, len(chunks), BATCH_SIZE):
            batch_ids = ids[i : i + BATCH_SIZE]
            batch_docs = documents[i : i + BATCH_SIZE]
            batch_meta = metadatas[i : i + BATCH_SIZE]

            col.upsert(
                ids=batch_ids,
                documents=batch_docs,
                metadatas=batch_meta,
            )
            added += len(batch_ids)
            print(f"  📦 Embedded batch {i // BATCH_SIZE + 1}: {added}/{len(chunks)} chunks")

            # Throttle untuk rate limit Gemini free tier (15 req/menit)
            if i + BATCH_SIZE < len(chunks):
                time.sleep(2)

        print(f"  ✅ Total {added} chunks indexed in collection '{self.collection_name}'")
        return added

    def query(
        self,
        query_text: str,
        top_k: int = RETRIEVAL_TOP_K,
        filter_source: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query collection untuk top-K paling relevan.

        Args:
            query_text: pertanyaan dalam natural language
            top_k: berapa hasil teratas yang dikembalikan
            filter_source: filter by source ('ASVS' atau 'NIST'), None = all

        Returns:
            List of dicts dengan keys: chunk_id, content, metadata, distance
        """
        where = {"source": filter_source} if filter_source else None

        # Gunakan Client baru dan RETRIEVAL_QUERY untuk query (lebih akurat)
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.embed_content(
            model=EMBEDDING_MODEL,
            contents=query_text,
            config=types.EmbedContentConfig(
                task_type="RETRIEVAL_QUERY"
            )
        )
        query_embedding = response.embeddings[0].values

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        # Format hasil
        formatted = []
        for i in range(len(results["ids"][0])):
            formatted.append({
                "chunk_id": results["ids"][0][i],
                "content": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if "distances" in results else None,
                "similarity": 1.0 - results["distances"][0][i] if "distances" in results else None,
            })

        return formatted

    def stats(self) -> dict[str, Any]:
        """Return statistik collection."""
        col = self.collection
        return {
            "collection_name": col.name,
            "total_chunks": col.count(),
            "persist_dir": str(self.persist_dir),
            "embedding_model": EMBEDDING_MODEL,
        }