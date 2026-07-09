"""Ingest curated seed records into the processed knowledge base."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import (
    AUXILIARY_PROCESSED_DIR,
    ERC_PROCESSED_DIR,
    REGISTRY_DIR,
    SEEDS_DIR,
    THREAT_PATTERN_PROCESSED_DIR,
    VULN_PROCESSED_DIR,
)
from src.mas4mbts.knowledge.validators import (
    validate_auxiliary,
    validate_erc,
    validate_threat_pattern,
    validate_vulnerability,
)
from src.mas4mbts.utils.json_io import read_json, write_json


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ingest_erc_seed(path: Path) -> dict[str, Any]:
    record = read_json(path)
    validate_erc(record)
    target = ERC_PROCESSED_DIR / record["id"] / "metadata.json"
    write_json(target, record)
    return {"kind": "erc_standard", "id": record["id"], "path": str(target)}


def ingest_vulnerability_seed(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path)
    records = payload.get("records", [])
    ingested = []
    for record in records:
        validate_vulnerability(record)
        target = VULN_PROCESSED_DIR / f"{record['id']}.json"
        write_json(target, record)
        ingested.append({"kind": "vulnerability", "id": record["id"], "path": str(target)})
    return ingested


def ingest_threat_pattern_seed(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path)
    records = payload.get("records", [])
    ingested = []
    for record in records:
        validate_threat_pattern(record)
        target = THREAT_PATTERN_PROCESSED_DIR / f"{record['id']}.json"
        write_json(target, record)
        ingested.append({"kind": "threat_pattern", "id": record["id"], "path": str(target)})
    return ingested


def ingest_auxiliary_seed(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path)
    records = payload.get("records", [])
    ingested = []
    for record in records:
        validate_auxiliary(record)
        target = AUXILIARY_PROCESSED_DIR / f"{record['id']}.json"
        write_json(target, record)
        ingested.append({"kind": "auxiliary", "id": record["id"], "path": str(target)})
    return ingested


def ingest_all_seeds() -> dict[str, Any]:
    items: list[dict[str, Any]] = []

    for path in sorted((SEEDS_DIR / "erc_standards").glob("*.json")):
        items.append(ingest_erc_seed(path))

    for path in sorted((SEEDS_DIR / "vulnerabilities").glob("*.json")):
        items.extend(ingest_vulnerability_seed(path))

    for path in sorted((SEEDS_DIR / "threat_patterns").glob("*.json")):
        items.extend(ingest_threat_pattern_seed(path))

    for path in sorted((SEEDS_DIR / "auxiliary").glob("*.json")):
        items.extend(ingest_auxiliary_seed(path))

    status = {"last_run": utc_now(), "mode": "offline_seed", "items": items}
    write_json(REGISTRY_DIR / "ingestion_status.json", status)
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest curated seed records into the processed knowledge base.")
    parser.parse_args()
    status = ingest_all_seeds()
    print(f"Ingested {len(status['items'])} knowledge records from seeds.")


if __name__ == "__main__":
    main()
