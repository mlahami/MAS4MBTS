"""Tiny lexical retriever for the deterministic JSONL index."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import INDEX_DIR


TOKEN_RE = re.compile(r"[A-Za-z0-9_:-]+")


def tokenize(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def load_documents(path: Path | None = None) -> list[dict[str, Any]]:
    index_path = path or INDEX_DIR / "documents.jsonl"
    if not index_path.exists():
        raise FileNotFoundError(f"Index not found: {index_path}. Run index_builder first.")
    return [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def retrieve(query: str, k: int = 5, erc: str | None = None, kind: str | None = None) -> list[dict[str, Any]]:
    query_tokens = tokenize(query)
    scored = []
    for document in load_documents():
        if kind and document["kind"] != kind:
            continue
        if erc:
            metadata = document.get("metadata", {})
            erc_value = metadata.get("erc")
            applicable_to = metadata.get("applicable_to", [])
            if erc_value and erc_value != erc:
                continue
            if applicable_to and erc not in applicable_to:
                continue
        doc_tokens = tokenize(document["title"] + " " + document["text"])
        score = len(query_tokens & doc_tokens)
        if score > 0:
            scored.append((score, document["id"], document))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [document for _, _, document in scored[:k]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Query the deterministic JSONL knowledge index.")
    parser.add_argument("query", help="Search query.")
    parser.add_argument("--erc", help="Optional ERC filter, e.g. ERC-20.")
    parser.add_argument("--kind", help="Optional kind filter: erc_standard, vulnerability, threat_pattern.")
    parser.add_argument("-k", type=int, default=5, help="Number of results.")
    args = parser.parse_args()

    results = retrieve(args.query, k=args.k, erc=args.erc, kind=args.kind)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
