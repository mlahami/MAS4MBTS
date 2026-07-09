"""Collect online source artifacts into knowledge_base/raw."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.mas4mbts.knowledge.collectors import (
    collect_all_erc_specs,
    collect_all_owasp_scs,
    collect_all_swc_registry,
    collect_cvss_pages,
    collect_erc_specs,
    collect_mitre_attack_pages,
    collect_nist_pages,
    collect_owasp_pages,
    collect_swc_registry,
)
from src.mas4mbts.knowledge.snapshot import utc_now, write_snapshot_manifest


def parse_erc_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def default_snapshot_id() -> str:
    return "raw_snapshot_" + utc_now().replace(":", "-")


def collect_sources(
    ercs: list[str] | None,
    discover_ercs: bool,
    all_ercs: bool,
    include_swc: bool,
    all_swc: bool,
    include_owasp: bool,
    all_owasp: bool,
    include_mitre: bool,
    include_cvss: bool,
    include_nist: bool,
    limit: int | None,
    snapshot_id: str | None,
    ref: str | None,
) -> Path:
    source_records = []

    if all_ercs:
        source_records.append(collect_all_erc_specs(limit=limit, ref=ref))
    elif ercs or discover_ercs:
        source_records.append(collect_erc_specs(erc_numbers=ercs, limit=limit if discover_ercs else None, ref=ref))

    if all_swc:
        source_records.append(collect_all_swc_registry(limit=limit, ref=ref))
    elif include_swc:
        source_records.append(collect_swc_registry(limit=limit, ref=ref))

    if all_owasp:
        source_records.append(collect_all_owasp_scs(limit=limit, ref=ref))
    elif include_owasp:
        source_records.append(collect_owasp_pages(limit=limit))

    if include_mitre:
        source_records.append(collect_mitre_attack_pages(limit=limit))

    if include_cvss:
        source_records.append(collect_cvss_pages(limit=limit))

    if include_nist:
        source_records.append(collect_nist_pages(limit=limit))

    if not source_records:
        raise ValueError(
            "No sources selected. Use --ercs, --discover-ercs, --all-ercs, --include-swc, --all-swc, --include-owasp, --all-owasp, --include-mitre, --include-cvss, or --include-nist."
        )

    return write_snapshot_manifest(snapshot_id or default_snapshot_id(), source_records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect online source artifacts into knowledge_base/raw.")
    parser.add_argument("--ercs", help="Comma-separated ERC numbers to fetch, e.g. 20,721,1155,4626.")
    parser.add_argument("--discover-ercs", action="store_true", help="Discover ERC markdown files from ethereum/ERCs.")
    parser.add_argument("--all-ercs", action="store_true", help="Download ethereum/ERCs archive and extract all ERC markdown files.")
    parser.add_argument("--include-swc", action="store_true", help="Collect raw SWC registry files.")
    parser.add_argument("--all-swc", action="store_true", help="Download SWC-registry archive and extract all markdown/json/yaml files.")
    parser.add_argument("--include-owasp", action="store_true", help="Collect configured OWASP Smart Contract Security pages.")
    parser.add_argument("--all-owasp", action="store_true", help="Download OWASP/owasp-scs archive and extract markdown/json/yaml files.")
    parser.add_argument("--include-mitre", action="store_true", help="Collect configured MITRE ATT&CK pages.")
    parser.add_argument("--include-cvss", action="store_true", help="Collect configured FIRST CVSS pages.")
    parser.add_argument("--include-nist", action="store_true", help="Collect configured NIST SP 800-53 pages.")
    parser.add_argument("--limit", type=int, help="Limit discovered files/pages per source for smoke tests.")
    parser.add_argument("--snapshot-id", help="Optional deterministic snapshot id.")
    parser.add_argument("--ref", help="Optional Git ref/branch for GitHub sources.")
    args = parser.parse_args()

    manifest_path = collect_sources(
        ercs=parse_erc_list(args.ercs),
        discover_ercs=args.discover_ercs,
        all_ercs=args.all_ercs,
        include_swc=args.include_swc,
        all_swc=args.all_swc,
        include_owasp=args.include_owasp,
        all_owasp=args.all_owasp,
        include_mitre=args.include_mitre,
        include_cvss=args.include_cvss,
        include_nist=args.include_nist,
        limit=args.limit,
        snapshot_id=args.snapshot_id,
        ref=args.ref,
    )
    print(f"Wrote raw snapshot manifest: {manifest_path}")


if __name__ == "__main__":
    main()
