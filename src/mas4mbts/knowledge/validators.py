"""Lightweight validation for knowledge records.

The project can use jsonschema when installed, but the ingestion chain keeps a
minimal stdlib validator so that initial experiments remain reproducible.
"""

from __future__ import annotations

from typing import Any


ERC_REQUIRED = [
    "id",
    "erc",
    "eip",
    "title",
    "status",
    "category",
    "source",
    "summary",
    "functions",
    "events",
    "assets",
    "security_properties",
]

VULNERABILITY_REQUIRED = [
    "id",
    "name",
    "category",
    "description",
    "severity",
    "cwe",
    "swc",
    "owasp",
    "source",
]

THREAT_PATTERN_REQUIRED = [
    "id",
    "name",
    "description",
    "applicable_to",
    "related_entry_points",
    "stride",
    "vulnerability",
    "security_property",
    "test_objective",
    "countermeasure",
]

AUXILIARY_REQUIRED = [
    "id",
    "kind",
    "name",
    "role",
    "description",
    "source",
    "applies_to",
]


def require_fields(record: dict[str, Any], required: list[str], record_type: str) -> None:
    missing = [field for field in required if field not in record]
    if missing:
        raise ValueError(f"{record_type} {record.get('id', '<unknown>')} missing fields: {', '.join(missing)}")


def validate_erc(record: dict[str, Any]) -> None:
    require_fields(record, ERC_REQUIRED, "ERC record")
    for field in ["functions", "events", "assets", "security_properties"]:
        if not isinstance(record[field], list):
            raise TypeError(f"ERC record {record['id']} field must be a list: {field}")


def validate_vulnerability(record: dict[str, Any]) -> None:
    require_fields(record, VULNERABILITY_REQUIRED, "Vulnerability record")


def validate_threat_pattern(record: dict[str, Any]) -> None:
    require_fields(record, THREAT_PATTERN_REQUIRED, "Threat pattern")
    for field in ["applicable_to", "related_entry_points"]:
        if not isinstance(record[field], list):
            raise TypeError(f"Threat pattern {record['id']} field must be a list: {field}")


def validate_auxiliary(record: dict[str, Any]) -> None:
    require_fields(record, AUXILIARY_REQUIRED, "Auxiliary record")
    if not isinstance(record["applies_to"], list):
        raise TypeError(f"Auxiliary record {record['id']} field must be a list: applies_to")
