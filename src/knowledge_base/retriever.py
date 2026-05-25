"""
Knowledge Base Retriever
========================
High-level interface untuk Cryptographic Mitigation Recommender Agent.

Menyediakan API yang mudah untuk:
- Query KB berdasarkan threat description
- Filter hasil berdasarkan CWE, source, dll.
- Format hasil untuk dikonsumsi oleh agent (sebagai context dalam prompt)
"""

from typing import Any

from src.config import RETRIEVAL_MIN_RELEVANCE, RETRIEVAL_TOP_K
from src.knowledge_base.vectorstore import VectorStore


class KnowledgeBaseRetriever:
    """
    High-level retriever untuk Crypto Mitigation Recommender Agent.

    Usage:
        retriever = KnowledgeBaseRetriever()
        results = retriever.retrieve_for_threat(
            threat_title="Weak Password Hashing",
            threat_description="System uses MD5 to hash user passwords",
            cwe_id="CWE-916"
        )
    """

    def __init__(self, vectorstore: VectorStore | None = None):
        self.vectorstore = vectorstore or VectorStore()

    def retrieve_for_threat(
        self,
        threat_title: str,
        threat_description: str,
        cwe_id: str | None = None,
        top_k: int = RETRIEVAL_TOP_K,
    ) -> list[dict[str, Any]]:
        """
        Retrieve chunks paling relevan untuk threat tertentu.

        Strategy:
        1. Compose query yang menggabungkan title + description + CWE
        2. Query vector store dengan top_k
        3. Filter berdasarkan relevance threshold
        4. Return formatted results

        Args:
            threat_title: judul threat (mis. "Weak Password Hashing")
            threat_description: deskripsi singkat threat
            cwe_id: CWE ID terkait (mis. "CWE-916")
            top_k: jumlah hasil teratas

        Returns:
            List of relevant chunks with similarity scores.
        """
        # Compose query yang information-rich
        query_parts = [threat_title]
        if threat_description:
            query_parts.append(threat_description)
        if cwe_id:
            query_parts.append(f"Related to {cwe_id}")

        query = " ".join(query_parts)

        results = self.vectorstore.query(query, top_k=top_k)

        # Filter berdasarkan minimum relevance
        filtered = [
            r for r in results
            if r["similarity"] is None or r["similarity"] >= RETRIEVAL_MIN_RELEVANCE
        ]

        return filtered

    def retrieve_hybrid(
        self,
        query: str,
        top_k: int = RETRIEVAL_TOP_K,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Retrieve dari ASVS dan NIST secara terpisah, lalu gabungkan.
        Berguna kalau ingin pastikan ada coverage dari kedua sumber.
        """
        asvs_results = self.vectorstore.query(
            query, top_k=top_k, filter_source="OWASP_ASVS"
        )
        nist_results = self.vectorstore.query(
            query, top_k=top_k, filter_source="NIST_800-53"
        )

        return {
            "asvs": asvs_results,
            "nist": nist_results,
        }

    def format_as_context(
        self,
        results: list[dict[str, Any]],
        max_chunks: int = 5,
    ) -> str:
        """
        Format hasil retrieval menjadi context string untuk LLM prompt.

        Output format:
            === REFERENCE 1 [ASVS V11.4.2 - similarity: 0.87] ===
            <content>

            === REFERENCE 2 [NIST IA-5 - similarity: 0.82] ===
            <content>
            ...
        """
        lines = []
        for i, r in enumerate(results[:max_chunks], 1):
            sim = r.get("similarity")
            sim_str = f"{sim:.2f}" if sim is not None else "N/A"
            chunk_id = r["chunk_id"]

            lines.append(f"=== REFERENCE {i} [{chunk_id} - similarity: {sim_str}] ===")
            lines.append(r["content"])
            lines.append("")

        return "\n".join(lines).strip()

    def stats(self) -> dict[str, Any]:
        """Return statistik knowledge base."""
        return self.vectorstore.stats()
