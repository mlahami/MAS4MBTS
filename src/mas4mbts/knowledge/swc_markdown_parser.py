"""Parse SWC markdown entries into vulnerability knowledge records."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


SWC_ID_RE = re.compile(r"(SWC-\d+)", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-(\d+):?\s*([^\]\n]+)?", re.IGNORECASE)


def extract_section(markdown: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(markdown)
    if not match:
        return ""
    next_heading = re.search(r"^##\s+", markdown[match.end() :], re.MULTILINE)
    if not next_heading:
        return markdown[match.end() :].strip()
    return markdown[match.end() : match.end() + next_heading.start()].strip()


def compact_markdown(text: str, max_chars: int = 1600) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"\[[^\]]+\]\([^)]+\)", lambda m: m.group(0).split("](")[0].lstrip("["), text)
    compact = " ".join(text.split())
    return compact[:max_chars].rstrip()


def parse_title(markdown: str, fallback: str) -> str:
    title_section = extract_section(markdown, "Title")
    if title_section:
        return " ".join(title_section.splitlines()).strip()
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    return match.group(1).strip() if match else fallback


def parse_swc_markdown(path: Path) -> dict[str, Any]:
    markdown = path.read_text(encoding="utf-8")
    swc_match = SWC_ID_RE.search(path.name)
    swc_id = swc_match.group(1).upper() if swc_match else path.stem.upper()
    title = parse_title(markdown, swc_id)
    relationships = extract_section(markdown, "Relationships")
    cwe_match = CWE_RE.search(relationships)
    cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else "N/A"
    cwe_name = cwe_match.group(2).strip() if cwe_match and cwe_match.group(2) else ""
    description = compact_markdown(extract_section(markdown, "Description"))
    remediation = compact_markdown(extract_section(markdown, "Remediation"))

    return {
        "id": f"VULN-{swc_id}",
        "name": title,
        "category": cwe_name or "Smart contract weakness",
        "description": description or title,
        "severity": "unknown",
        "cwe": cwe,
        "swc": swc_id,
        "owasp": "N/A",
        "source": {
            "source_id": "swc_registry",
            "raw_path": str(path),
            "maintenance_status": "not_actively_maintained",
            "note": "SWC is retained as a historical smart contract weakness taxonomy.",
        },
        "remediation": remediation,
    }
