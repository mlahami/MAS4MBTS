"""Fetch an ERC specification from the official GitHub raw source.

This command is intentionally opt-in and is not used by the reproducible
offline seed pipeline. It gives the future cron job a small, testable unit.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from src.mas4mbts.knowledge.collectors import normalize_erc_number, source_by_id
from src.mas4mbts.knowledge.http_client import fetch_text
from src.mas4mbts.knowledge.paths import RAW_DIR
from src.mas4mbts.knowledge.snapshot import utc_now


def fetch_erc(erc_number: str, output_dir: Path | None = None) -> Path:
    source = source_by_id("ethereum_ercs_repo")
    number = normalize_erc_number(erc_number)
    url = source["raw_url_template"].format(erc_number=number)
    target_dir = output_dir or RAW_DIR / "ercs"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"erc-{number}.md"
    content = fetch_text(url).text
    header = f"<!-- fetched_at: {utc_now()} source: {url} -->\n"
    target.write_text(header + content, encoding="utf-8")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch one ERC markdown specification from ethereum/ERCs.")
    parser.add_argument("erc_number", help="ERC number, e.g. 20, 721, 1155, 4626.")
    args = parser.parse_args()
    target = fetch_erc(args.erc_number)
    print(f"Fetched ERC specification: {target}")


if __name__ == "__main__":
    main()
