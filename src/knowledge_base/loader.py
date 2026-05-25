"""
Document Loader
===============
Memuat dokumen sumber knowledge base:
- OWASP ASVS 5.0 V11 Cryptography (markdown)
- NIST SP 800-53 SC family + IA-5/IA-7 (JSON)
"""

import json
import re
from pathlib import Path
from typing import Any


def load_asvs_markdown(file_path: Path) -> dict[str, Any]:
    """
    Parse ASVS markdown file dan return structured dict.

    ASVS markdown structure:
        # OWASP ASVS 5.0 — V11 Cryptography
        ## V11.X Section Name
        ### V11.X.Y (Level N)
        **Requirement:** ...
        **Rationale:** ...
        **Implementation Guidance:** ...

    Returns:
        {
            "title": "...",
            "version": "5.0",
            "chapter": "V11",
            "sections": [
                {
                    "section_id": "V11.1",
                    "section_title": "Cryptographic Inventory and Documentation",
                    "requirements": [
                        {
                            "id": "V11.1.1",
                            "level": "1",
                            "requirement": "...",
                            "rationale": "...",
                            "implementation_guidance": "...",
                            "related_cwe": ["CWE-1240"],
                        }
                    ]
                }
            ]
        }
    """
    content = file_path.read_text(encoding="utf-8")

    result = {
        "title": "OWASP ASVS 5.0 V11 Cryptography",
        "version": "5.0",
        "chapter": "V11",
        "source_path": str(file_path),
        "sections": [],
    }

    # Split by section (## V11.X)
    section_pattern = re.compile(
        r"^## (V11\.\d+)\s+(.+?)\n(.*?)(?=^## V11\.\d+|\Z)",
        re.MULTILINE | re.DOTALL,
    )

    for match in section_pattern.finditer(content):
        section_id = match.group(1).strip()
        section_title = match.group(2).strip()
        section_body = match.group(3).strip()

        section = {
            "section_id": section_id,
            "section_title": section_title,
            "requirements": [],
        }

        # Split by requirement (### V11.X.Y)
        req_pattern = re.compile(
            r"^### (V11\.\d+\.\d+)\s+\(Level\s+(\d+)\)\n(.*?)(?=^### V11\.\d+\.\d+|\Z)",
            re.MULTILINE | re.DOTALL,
        )

        for req_match in req_pattern.finditer(section_body):
            req_id = req_match.group(1).strip()
            level = req_match.group(2).strip()
            req_body = req_match.group(3).strip()

            requirement = {
                "id": req_id,
                "level": level,
                "requirement": _extract_field(req_body, "Requirement"),
                "rationale": _extract_field(req_body, "Rationale"),
                "implementation_guidance": _extract_field(
                    req_body, "Implementation Guidance"
                ),
                "related_cwe": _extract_cwe(req_body),
                "related_nist": _extract_nist(req_body),
                "raw_body": req_body,
            }
            section["requirements"].append(requirement)

        result["sections"].append(section)

    return result


def load_nist_json(file_path: Path) -> dict[str, Any]:
    """
    Memuat NIST 800-53 JSON file.

    Returns:
        Dictionary dengan structure dari file JSON (sudah terstruktur).
    """
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return data


def _extract_field(body: str, field_name: str) -> str:
    """Ekstrak nilai dari format '**Field Name:** ...'"""
    pattern = rf"\*\*{re.escape(field_name)}:\*\*\s*(.*?)(?=\n\*\*|\n###|\Z)"
    match = re.search(pattern, body, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""


def _extract_cwe(body: str) -> list[str]:
    """Ekstrak CWE references dari body."""
    cwe_pattern = re.compile(r"CWE-(\d+)")
    return list(set([f"CWE-{m}" for m in cwe_pattern.findall(body)]))


def _extract_nist(body: str) -> list[str]:
    """Ekstrak NIST references dari body."""
    # Pattern untuk "Related NIST: SP 800-XX" atau "SP 800-XX"
    nist_pattern = re.compile(r"SP\s*800-\d+[a-zA-Z]?")
    return list(set(nist_pattern.findall(body)))
