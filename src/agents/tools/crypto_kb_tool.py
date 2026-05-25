"""
Crypto Knowledge Base Tool
==========================
CrewAI tool wrapper untuk KnowledgeBaseRetriever.

Memberikan akses ke knowledge base (OWASP ASVS V11 + NIST 800-53 SC/IA)
sebagai tool yang bisa di-invoke oleh CrewAI agent.
"""

from typing import Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from src.knowledge_base import KnowledgeBaseRetriever


# ============================================================================
# Module-level singleton — avoid re-init ChromaDB per call
# ============================================================================

_RETRIEVER_INSTANCE: Optional[KnowledgeBaseRetriever] = None


def get_retriever() -> KnowledgeBaseRetriever:
    """Get singleton retriever instance (lazy init)."""
    global _RETRIEVER_INSTANCE
    if _RETRIEVER_INSTANCE is None:
        _RETRIEVER_INSTANCE = KnowledgeBaseRetriever()
    return _RETRIEVER_INSTANCE


# ============================================================================
# Input Schema
# ============================================================================

class CryptoKnowledgeBaseInput(BaseModel):
    """Input schema untuk CryptoKnowledgeBaseTool."""
    
    threat_title: str = Field(
        ...,
        description="Judul ancaman, mis. 'Weak Password Hashing'",
    )
    
    threat_description: str = Field(
        ...,
        description="Deskripsi detail ancaman",
    )
    
    cwe_id: Optional[str] = Field(
        default=None,
        description="CWE identifier kalau ada, mis. 'CWE-916'",
    )
    
    top_k: int = Field(
        default=5,
        description="Jumlah chunk teratas yang dikembalikan (default 5)",
        ge=1,
        le=15,
    )


# ============================================================================
# Tool
# ============================================================================

class CryptoKnowledgeBaseTool(BaseTool):
    """
    Tool untuk query knowledge base kriptografi.
    
    Mengembalikan chunks paling relevan dari OWASP ASVS V11 Cryptography
    dan NIST 800-53 SC/IA controls untuk threat tertentu.
    """
    
    name: str = "crypto_knowledge_base_search"
    description: str = (
        "Cari standar kriptografi yang relevan untuk satu ancaman keamanan. "
        "Mengembalikan referensi dari OWASP ASVS 5.0 V11 Cryptography dan "
        "NIST 800-53 SC/IA controls. "
        "Gunakan tool ini SEBELUM merumuskan rekomendasi mitigasi untuk memastikan "
        "rekomendasi tertelusuri ke standar internasional. "
        "Input: threat_title (string), threat_description (string), "
        "cwe_id (optional string), top_k (optional integer, default 5)."
    )
    args_schema: Type[BaseModel] = CryptoKnowledgeBaseInput
    
    def _run(
        self,
        threat_title: str,
        threat_description: str,
        cwe_id: Optional[str] = None,
        top_k: int = 5,
    ) -> str:
        """
        Execute knowledge base search dan return formatted results sebagai string.
        
        CrewAI tools harus return string (untuk dikonsumsi LLM sebagai context).
        """
        try:
            retriever = get_retriever()
            results = retriever.retrieve_for_threat(
                threat_title=threat_title,
                threat_description=threat_description,
                cwe_id=cwe_id,
                top_k=top_k,
            )
        except Exception as e:
            return f"ERROR: Knowledge base query failed: {e}"
        
        if not results:
            return (
                f"No relevant standards found for threat: '{threat_title}'. "
                f"Consider generating mitigation based on general cryptographic best practices."
            )
        
        # Format hasil sebagai context yang LLM-friendly
        output_lines = [
            f"=== KNOWLEDGE BASE RESULTS untuk threat: '{threat_title}' ===",
            f"Found {len(results)} relevant standard reference(s):",
            "",
        ]
        
        for i, r in enumerate(results, 1):
            sim = r.get("similarity")
            sim_str = f"{sim:.3f}" if sim is not None else "N/A"
            source_meta = r.get("metadata", {}).get("source", "")
            
            output_lines.append(
                f"--- REFERENCE {i} [chunk_id: {r['chunk_id']}, "
                f"source: {source_meta}, similarity: {sim_str}] ---"
            )
            output_lines.append(r["content"])
            output_lines.append("")
        
        return "\n".join(output_lines).strip()
    
    async def _arun(self, *args, **kwargs):
        """Async version (not implemented, CrewAI calls _run by default)."""
        return self._run(*args, **kwargs)
