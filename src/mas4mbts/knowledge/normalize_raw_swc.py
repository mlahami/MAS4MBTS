"""Normalize raw SWC markdown files into processed vulnerability records."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.mas4mbts.knowledge.paths import RAW_DIR, VULN_PROCESSED_DIR
from src.mas4mbts.knowledge.swc_markdown_parser import parse_swc_markdown
from src.mas4mbts.knowledge.validators import validate_vulnerability
from src.mas4mbts.utils.json_io import write_json


def normalize_raw_swc(raw_dir: Path | None = None) -> list[Path]:
    source_dir = raw_dir or RAW_DIR / "swc"
    outputs: list[Path] = []
    for path in sorted(source_dir.rglob("SWC-*.md")):
        record = parse_swc_markdown(path)
        validate_vulnerability(record)
        target = VULN_PROCESSED_DIR / f"{record['id']}.json"
        write_json(target, record)
        outputs.append(target)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize raw SWC markdown files into vulnerability records.")
    parser.add_argument("--raw-dir", type=Path, help="Optional directory containing SWC-*.md files.")
    args = parser.parse_args()
    outputs = normalize_raw_swc(raw_dir=args.raw_dir)
    print(f"Normalized {len(outputs)} raw SWC files.")


if __name__ == "__main__":
    main()
