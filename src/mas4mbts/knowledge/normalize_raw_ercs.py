"""Normalize raw ERC markdown files into processed ERC knowledge records."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.mas4mbts.knowledge.erc_markdown_parser import parse_erc_markdown
from src.mas4mbts.knowledge.paths import ERC_PROCESSED_DIR, RAW_DIR
from src.mas4mbts.knowledge.validators import validate_erc
from src.mas4mbts.utils.json_io import write_json


def normalize_raw_ercs(raw_dir: Path | None = None) -> list[Path]:
    source_dir = raw_dir or RAW_DIR / "ercs"
    outputs: list[Path] = []
    for path in sorted(source_dir.rglob("erc-*.md")):
        record = parse_erc_markdown(path)
        validate_erc(record)
        target = ERC_PROCESSED_DIR / record["id"] / "metadata.json"
        write_json(target, record)
        outputs.append(target)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize raw ERC markdown files into processed records.")
    parser.add_argument("--raw-dir", type=Path, help="Optional directory containing erc-*.md files.")
    args = parser.parse_args()
    outputs = normalize_raw_ercs(raw_dir=args.raw_dir)
    print(f"Normalized {len(outputs)} raw ERC files.")


if __name__ == "__main__":
    main()
