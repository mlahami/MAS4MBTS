"""Chunk deterministic knowledge documents for RAG retrieval."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import INDEX_DIR
from src.mas4mbts.utils.json_io import write_json, write_jsonl


SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def load_documents(path: Path | None = None) -> list[dict[str, Any]]:
    documents_path = path or INDEX_DIR / "documents.jsonl"
    if not documents_path.exists():
        raise FileNotFoundError(f"Document index not found: {documents_path}")
    return [json.loads(line) for line in documents_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def split_sentences(text: str) -> list[str]:
    return [part.strip() for part in SENTENCE_RE.split(text) if part.strip()]


def count_tokens(text: str) -> int:
    return len(text.split())


def chunk_text(text: str, max_tokens: int = 180, overlap_tokens: int = 35) -> list[str]:
    """Split text into overlapping chunks while preserving sentence boundaries."""
    if max_tokens <= 0:
        raise ValueError("max_tokens must be positive")
    if overlap_tokens < 0:
        raise ValueError("overlap_tokens cannot be negative")
    if overlap_tokens >= max_tokens:
        raise ValueError("overlap_tokens must be smaller than max_tokens")

    sentences = split_sentences(" ".join(text.split()))
    if not sentences:
        return []

    chunks: list[str] = []
    current: list[str] = []
    current_tokens = 0

    for sentence in sentences:
        sentence_tokens = count_tokens(sentence)
        if sentence_tokens > max_tokens:
            words = sentence.split()
            for start in range(0, len(words), max_tokens - overlap_tokens):
                part = " ".join(words[start : start + max_tokens])
                if part:
                    chunks.append(part)
            current = []
            current_tokens = 0
            continue

        if current and current_tokens + sentence_tokens > max_tokens:
            chunk = " ".join(current)
            chunks.append(chunk)
            overlap_words = chunk.split()[-overlap_tokens:] if overlap_tokens else []
            current = [" ".join(overlap_words)] if overlap_words else []
            current_tokens = len(overlap_words)

        current.append(sentence)
        current_tokens += sentence_tokens

    if current:
        chunks.append(" ".join(current))

    return [chunk for chunk in chunks if chunk.strip()]


def make_chunk(document: dict[str, Any], chunk_index: int, text: str) -> dict[str, Any]:
    metadata = dict(document.get("metadata", {}))
    metadata.update(
        {
            "source_document_id": document["id"],
            "source_title": document.get("title", ""),
        }
    )
    return {
        "id": f"{document['id']}#chunk:{chunk_index:03d}",
        "document_id": document["id"],
        "kind": document["kind"],
        "title": document.get("title", ""),
        "text": text,
        "metadata": metadata,
    }


def build_chunks(max_tokens: int = 180, overlap_tokens: int = 35) -> dict[str, Any]:
    documents = load_documents()
    chunks: list[dict[str, Any]] = []
    for document in documents:
        full_text = f"{document.get('title', '')}. {document.get('text', '')}"
        for index, text in enumerate(chunk_text(full_text, max_tokens=max_tokens, overlap_tokens=overlap_tokens), start=1):
            chunks.append(make_chunk(document, index, text))

    chunks = sorted(chunks, key=lambda item: item["id"])
    write_jsonl(INDEX_DIR / "chunks.jsonl", chunks)

    manifest_path = INDEX_DIR / "chunk_manifest.json"
    manifest = {
        "index_type": "deterministic_chunks_jsonl",
        "source_documents_path": str(INDEX_DIR / "documents.jsonl"),
        "chunks_path": str(INDEX_DIR / "chunks.jsonl"),
        "document_count": len(documents),
        "chunk_count": len(chunks),
        "max_tokens": max_tokens,
        "overlap_tokens": overlap_tokens,
    }
    write_json(manifest_path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build chunked JSONL records from the deterministic document index.")
    parser.add_argument("--max-tokens", type=int, default=180)
    parser.add_argument("--overlap-tokens", type=int, default=35)
    args = parser.parse_args()

    manifest = build_chunks(max_tokens=args.max_tokens, overlap_tokens=args.overlap_tokens)
    print(f"Built {manifest['chunk_count']} chunks from {manifest['document_count']} documents.")


if __name__ == "__main__":
    main()
