"""Build a deterministic JSONL retrieval index from processed knowledge."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import (
    AUXILIARY_PROCESSED_DIR,
    ERC_PROCESSED_DIR,
    INDEX_DIR,
    THREAT_PATTERN_PROCESSED_DIR,
    VULN_PROCESSED_DIR,
)
from src.mas4mbts.utils.json_io import read_json, write_json, write_jsonl


def make_document(doc_id: str, kind: str, title: str, text: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc_id,
        "kind": kind,
        "title": title,
        "text": " ".join(text.split()),
        "metadata": metadata,
    }


def erc_documents() -> list[dict[str, Any]]:
    docs = []
    for path in sorted(ERC_PROCESSED_DIR.glob("*/metadata.json")):
        record = read_json(path)
        function_text = ", ".join(f"{f.get('name')} {f.get('signature')}" for f in record["functions"])
        asset_text = ", ".join(a.get("name", "") for a in record["assets"])
        property_text = " ".join(p.get("description", "") for p in record["security_properties"])
        text = f"{record['erc']} {record['title']}. {record['summary']} Functions: {function_text}. Assets: {asset_text}. Security properties: {property_text}"
        docs.append(
            make_document(
                doc_id=f"erc:{record['id']}",
                kind="erc_standard",
                title=f"{record['erc']} {record['title']}",
                text=text,
                metadata={
                    "erc": record["erc"],
                    "status": record["status"],
                    "source_url": record["source"].get("canonical_url", ""),
                    "path": str(path),
                },
            )
        )
    return docs


def vulnerability_documents() -> list[dict[str, Any]]:
    docs = []
    for path in sorted(VULN_PROCESSED_DIR.glob("*.json")):
        record = read_json(path)
        text = f"{record['name']}. {record['description']} Category: {record['category']}. CWE: {record['cwe']}. SWC: {record['swc']}. OWASP: {record['owasp']}."
        docs.append(
            make_document(
                doc_id=f"vulnerability:{record['id']}",
                kind="vulnerability",
                title=record["name"],
                text=text,
                metadata={
                    "severity": record["severity"],
                    "cwe": record["cwe"],
                    "swc": record["swc"],
                    "owasp": record["owasp"],
                    "path": str(path),
                },
            )
        )
    return docs


def threat_pattern_documents() -> list[dict[str, Any]]:
    docs = []
    for path in sorted(THREAT_PATTERN_PROCESSED_DIR.glob("*.json")):
        record = read_json(path)
        applicable = ", ".join(record["applicable_to"])
        entry_points = ", ".join(record["related_entry_points"])
        text = (
            f"{record['name']}. {record['description']} Applicable to: {applicable}. "
            f"Entry points: {entry_points}. STRIDE: {record['stride']}. "
            f"Vulnerability: {record['vulnerability']}. Security property: {record['security_property']}. "
            f"Test objective: {record['test_objective']}. Countermeasure: {record['countermeasure']}."
        )
        docs.append(
            make_document(
                doc_id=f"threat_pattern:{record['id']}",
                kind="threat_pattern",
                title=record["name"],
                text=text,
                metadata={
                    "applicable_to": record["applicable_to"],
                    "stride": record["stride"],
                    "cwe": record.get("cwe", ""),
                    "swc": record.get("swc", ""),
                    "owasp": record.get("owasp", ""),
                    "path": str(path),
                },
            )
        )
    return docs


def auxiliary_documents() -> list[dict[str, Any]]:
    docs = []
    for path in sorted(AUXILIARY_PROCESSED_DIR.glob("*.json")):
        record = read_json(path)
        applies_to = ", ".join(record.get("applies_to", []))
        guidelines = " ".join(record.get("usage_guidelines", []))
        mappings = " ".join(
            " ".join(str(value) for value in mapping.values()) for mapping in record.get("mappings", [])
        )
        fields = " ".join(
            " ".join(str(value) for value in field.values()) for field in record.get("fields", [])
        )
        text = (
            f"{record['name']}. {record['description']} Role: {record['role']}. "
            f"Applies to: {applies_to}. Fields: {fields}. Mappings: {mappings}. "
            f"Usage guidelines: {guidelines}."
        )
        docs.append(
            make_document(
                doc_id=f"auxiliary:{record['id']}",
                kind="auxiliary",
                title=record["name"],
                text=text,
                metadata={
                    "auxiliary_kind": record["kind"],
                    "role": record["role"],
                    "source_id": record["source"].get("source_id", ""),
                    "path": str(path),
                },
            )
        )
    return docs


def build_index() -> dict[str, Any]:
    documents = erc_documents() + vulnerability_documents() + threat_pattern_documents() + auxiliary_documents()
    documents = sorted(documents, key=lambda item: item["id"])
    write_jsonl(INDEX_DIR / "documents.jsonl", documents)
    manifest = {
        "index_type": "deterministic_jsonl",
        "document_count": len(documents),
        "documents_path": str(INDEX_DIR / "documents.jsonl"),
    }
    write_json(INDEX_DIR / "manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deterministic JSONL index from processed knowledge.")
    parser.parse_args()
    manifest = build_index()
    print(f"Built {manifest['index_type']} with {manifest['document_count']} documents.")


if __name__ == "__main__":
    main()
