"""Normalize raw OWASP SCS markdown files into vulnerability records."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.mas4mbts.knowledge.owasp_markdown_parser import parse_owasp_markdown
from src.mas4mbts.knowledge.paths import RAW_DIR, VULN_PROCESSED_DIR
from src.mas4mbts.knowledge.validators import validate_vulnerability
from src.mas4mbts.utils.json_io import write_json


def is_supported_owasp_file(path: Path) -> bool:
    normalized = str(path).replace("\\", "/")
    name = path.name
    return (
        "/docs/SCWE/" in normalized
        and name.startswith("SCWE-")
        and name.endswith(".md")
    ) or (
        "/docs/sctop10/" in normalized
        and name.startswith("SC")
        and name.endswith(".md")
        and "archive/" not in normalized
    )


def normalize_raw_owasp(raw_dir: Path | None = None) -> list[Path]:
    source_dir = raw_dir or RAW_DIR / "owasp"
    outputs: list[Path] = []
    for path in sorted(source_dir.rglob("*.md")):
        if not is_supported_owasp_file(path):
            continue
        record = parse_owasp_markdown(path)
        validate_vulnerability(record)
        target = VULN_PROCESSED_DIR / f"{record['id']}.json"
        write_json(target, record)
        outputs.append(target)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize raw OWASP SCS markdown files into vulnerability records.")
    parser.add_argument("--raw-dir", type=Path, help="Optional raw OWASP directory.")
    args = parser.parse_args()
    outputs = normalize_raw_owasp(raw_dir=args.raw_dir)
    print(f"Normalized {len(outputs)} raw OWASP files.")


if __name__ == "__main__":
    main()
