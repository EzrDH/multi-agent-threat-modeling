"""
Document Chunker
================
Memecah dokumen yang sudah ter-load menjadi chunk semantik per-kontrol.

Setiap chunk = 1 requirement ASVS atau 1 NIST control dengan metadata lengkap,
sehingga retrieval akan mengembalikan satu unit semantik yang utuh.
"""

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Chunk:
    """Representasi 1 chunk dari knowledge base."""

    chunk_id: str  # Unique ID, mis. "ASVS-V11.4.2" atau "NIST-SC-12"
    source: str  # "ASVS" atau "NIST"
    content: str  # Text content yang akan di-embed
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __repr__(self) -> str:
        preview = self.content[:80].replace("\n", " ")
        return f"Chunk({self.chunk_id}, {self.source}, '{preview}...')"


def chunk_asvs_controls(asvs_data: dict[str, Any]) -> list[Chunk]:
    """
    Chunk ASVS data — 1 requirement = 1 chunk.

    Content format (yang akan di-embed):
        [ASVS V11.X.Y - Level N]
        Section: <section title>

        Requirement: <req text>

        Rationale: <rationale text>

        Implementation Guidance: <guidance text>

        Related CWE: CWE-X, CWE-Y
        Related NIST: SP 800-XX
    """
    chunks: list[Chunk] = []

    for section in asvs_data.get("sections", []):
        section_id = section["section_id"]
        section_title = section["section_title"]

        for req in section.get("requirements", []):
            req_id = req["id"]
            chunk_id = f"ASVS-{req_id}"

            # Compose content untuk embedding
            content_parts = [
                f"[ASVS {req_id} - Level {req.get('level', '?')}]",
                f"Section: {section_id} {section_title}",
                "",
            ]

            if req.get("requirement"):
                content_parts.append(f"Requirement: {req['requirement']}")
                content_parts.append("")

            if req.get("rationale"):
                content_parts.append(f"Rationale: {req['rationale']}")
                content_parts.append("")

            if req.get("implementation_guidance"):
                content_parts.append(
                    f"Implementation Guidance: {req['implementation_guidance']}"
                )
                content_parts.append("")

            if req.get("related_cwe"):
                content_parts.append(f"Related CWE: {', '.join(req['related_cwe'])}")

            if req.get("related_nist"):
                content_parts.append(f"Related NIST: {', '.join(req['related_nist'])}")

            content = "\n".join(content_parts).strip()

            # Metadata untuk filtering & display di retrieval
            metadata = {
                "source": "OWASP_ASVS",
                "version": asvs_data.get("version", "5.0"),
                "chapter": asvs_data.get("chapter", "V11"),
                "section_id": section_id,
                "section_title": section_title,
                "control_id": req_id,
                "level": req.get("level", "1"),
                "related_cwe": ",".join(req.get("related_cwe", [])),
                "related_nist": ",".join(req.get("related_nist", [])),
            }

            chunks.append(
                Chunk(
                    chunk_id=chunk_id,
                    source="ASVS",
                    content=content,
                    metadata=metadata,
                )
            )

    return chunks


def chunk_nist_controls(nist_data: dict[str, Any]) -> list[Chunk]:
    """
    Chunk NIST data — 1 control = 1 chunk (termasuk semua enhancements).

    Content format:
        [NIST SC-12 - Cryptographic Key Establishment and Management]
        Family: SC (System and Communications Protection)

        Control: <control text>

        Enhancements:
        - SC-12(1) Availability: <text>
        - SC-12(2) Symmetric Keys: <text>

        Implementation Guidance: <guidance>

        Related CWE: CWE-X
        Related ASVS: V11.X.Y
    """
    chunks: list[Chunk] = []

    for control in nist_data.get("controls", []):
        ctrl_id = control["id"]
        chunk_id = f"NIST-{ctrl_id}"

        content_parts = [
            f"[NIST {ctrl_id} - {control.get('title', '')}]",
            f"Family: {control.get('family', '')} (NIST 800-53 Rev. 5)",
            "",
        ]

        if control.get("control_text"):
            content_parts.append(f"Control: {control['control_text']}")
            content_parts.append("")

        # Control enhancements
        if control.get("control_enhancements"):
            content_parts.append("Enhancements:")
            for enh in control["control_enhancements"]:
                content_parts.append(
                    f"- {enh['id']} {enh.get('title', '')}: {enh.get('text', '')}"
                )
            content_parts.append("")

        if control.get("implementation_guidance"):
            content_parts.append(
                f"Implementation Guidance: {control['implementation_guidance']}"
            )
            content_parts.append("")

        if control.get("related_cwe"):
            content_parts.append(f"Related CWE: {', '.join(control['related_cwe'])}")

        if control.get("related_asvs"):
            content_parts.append(f"Related ASVS: {', '.join(control['related_asvs'])}")

        content = "\n".join(content_parts).strip()

        metadata = {
            "source": "NIST_800-53",
            "version": "Rev.5",
            "control_id": ctrl_id,
            "title": control.get("title", ""),
            "family": control.get("family", ""),
            "related_cwe": ",".join(control.get("related_cwe", [])),
            "related_asvs": ",".join(control.get("related_asvs", [])),
        }

        chunks.append(
            Chunk(
                chunk_id=chunk_id,
                source="NIST",
                content=content,
                metadata=metadata,
            )
        )

    return chunks
