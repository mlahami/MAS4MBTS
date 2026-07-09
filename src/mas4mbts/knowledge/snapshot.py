"""Snapshot manifest helpers for raw knowledge collection."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import RAW_DIR
from src.mas4mbts.utils.json_io import write_json


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def write_raw_text(target: Path, content: str) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {
        "path": str(target),
        "bytes": len(content.encode("utf-8")),
        "sha256": sha256_text(content),
    }


def write_raw_bytes(target: Path, content: bytes) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return {
        "path": str(target),
        "bytes": len(content),
        "sha256": sha256_bytes(content),
    }


def create_snapshot_manifest(snapshot_id: str, source_records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot_id,
        "created_at": utc_now(),
        "raw_root": str(RAW_DIR),
        "source_records": source_records,
        "source_count": len(source_records),
        "file_count": sum(len(record.get("files", [])) for record in source_records),
    }


def write_snapshot_manifest(snapshot_id: str, source_records: list[dict[str, Any]]) -> Path:
    manifest = create_snapshot_manifest(snapshot_id, source_records)
    target = RAW_DIR / "manifests" / f"{snapshot_id}.json"
    write_json(target, manifest)
    return target
