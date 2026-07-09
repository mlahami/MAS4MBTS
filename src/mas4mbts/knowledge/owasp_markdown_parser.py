"""Parse OWASP Smart Contract Security markdown into vulnerability records."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


FRONT_MATTER_RE = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*", re.DOTALL)
CWE_RE = re.compile(r"CWE-(\d+):?\s*([^\]\n]+)?", re.IGNORECASE)


def parse_front_matter(markdown: str) -> dict[str, str]:
    match = FRONT_MATTER_RE.match(markdown)
    if not match:
        return {}
    metadata: dict[str, str] = {}
    for line in match.group("body").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata


def extract_section(markdown: str, heading: str) -> str:
    pattern = re.compile(rf"^#+\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(markdown)
    if not match:
        return ""
    next_heading = re.search(r"^#+\s+", markdown[match.end() :], re.MULTILINE)
    if not next_heading:
        return markdown[match.end() :].strip()
    return markdown[match.end() : match.end() + next_heading.start()].strip()


def compact_markdown(text: str, max_chars: int = 1800) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"\[[^\]]+\]\([^)]+\)", lambda m: m.group(0).split("](")[0].lstrip("["), text)
    compact = " ".join(text.split())
    return compact[:max_chars].rstrip()


def first_heading(markdown: str) -> str:
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    return match.group(1).strip() if match else ""


def infer_record_id(path: Path, metadata: dict[str, str]) -> str:
    if metadata.get("id"):
        return metadata["id"]
    match = re.match(r"(SC\d+)", path.stem, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return path.stem.upper()


def parse_owasp_markdown(path: Path) -> dict[str, Any]:
    markdown = path.read_text(encoding="utf-8")
    metadata = parse_front_matter(markdown)
    record_id = infer_record_id(path, metadata)
    title = metadata.get("title") or first_heading(markdown) or record_id
    relationships = extract_section(markdown, "Relationships")
    cwe_match = CWE_RE.search(relationships) or CWE_RE.search(markdown)
    cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else "N/A"
    cwe_name = cwe_match.group(2).strip() if cwe_match and cwe_match.group(2) else ""
    vulnerability = extract_section(markdown, "Vulnerability")
    description = extract_section(markdown, "Description") or vulnerability
    remediation = extract_section(markdown, "Remediation") or extract_section(markdown, "Best Practices & Mitigations")

    category = "OWASP Smart Contract Top 10" if "sctop10" in str(path).lower() else "OWASP Smart Contract Weakness"

    return {
        "id": f"VULN-OWASP-{record_id}",
        "name": title,
        "category": cwe_name or category,
        "description": compact_markdown(description or title),
        "severity": "unknown",
        "cwe": cwe,
        "swc": "N/A",
        "owasp": record_id,
        "source": {
            "source_id": "owasp_smart_contract_security",
            "raw_path": str(path),
            "record_family": "sctop10" if "sctop10" in str(path).lower() else "scwe",
        },
        "remediation": compact_markdown(remediation),
    }
