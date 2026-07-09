"""Hybrid RAG retriever with BM25, deterministic dense vectors, and RRF fusion.

The dense scorer intentionally uses a local deterministic hashing embedder.
This keeps the first implementation reproducible and offline. The same public
functions can later be backed by OpenAI, Mistral, sentence-transformers, FAISS,
or Chroma without changing the threat-modeling agent interface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import INDEX_DIR


TOKEN_RE = re.compile(r"[A-Za-z0-9_:-]+")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def load_chunks(path: Path | None = None) -> list[dict[str, Any]]:
    chunks_path = path or INDEX_DIR / "chunks.jsonl"
    if not chunks_path.exists():
        raise FileNotFoundError(f"Chunk index not found: {chunks_path}. Run chunker first.")
    return [json.loads(line) for line in chunks_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def metadata_matches(chunk: dict[str, Any], erc: str | None = None, kind: str | None = None) -> bool:
    if kind and chunk.get("kind") != kind:
        return False
    if not erc:
        return True

    metadata = chunk.get("metadata", {})
    erc_value = metadata.get("erc")
    applicable_to = metadata.get("applicable_to", [])
    if erc_value and erc_value != erc:
        return False
    if applicable_to and erc not in applicable_to:
        return False
    return True


class BM25Index:
    """Small in-memory BM25 implementation for reproducible sparse retrieval."""

    def __init__(self, chunks: list[dict[str, Any]], k1: float = 1.5, b: float = 0.75) -> None:
        self.chunks = chunks
        self.k1 = k1
        self.b = b
        self.documents = [tokenize(f"{chunk.get('title', '')} {chunk.get('text', '')}") for chunk in chunks]
        self.term_frequencies = [Counter(document) for document in self.documents]
        self.document_lengths = [len(document) for document in self.documents]
        self.average_length = sum(self.document_lengths) / len(self.document_lengths) if self.document_lengths else 0.0
        self.document_frequencies = self._document_frequencies()

    def _document_frequencies(self) -> Counter[str]:
        frequencies: Counter[str] = Counter()
        for document in self.documents:
            frequencies.update(set(document))
        return frequencies

    def score(self, query: str, index: int) -> float:
        query_terms = tokenize(query)
        if not query_terms or not self.documents[index]:
            return 0.0
        score = 0.0
        document_count = len(self.documents)
        document_length = self.document_lengths[index]
        term_frequency = self.term_frequencies[index]
        for term in query_terms:
            if term not in term_frequency:
                continue
            df = self.document_frequencies[term]
            idf = math.log(1 + (document_count - df + 0.5) / (df + 0.5))
            frequency = term_frequency[term]
            denominator = frequency + self.k1 * (1 - self.b + self.b * document_length / max(self.average_length, 1.0))
            score += idf * (frequency * (self.k1 + 1)) / denominator
        return score

    def rank(self, query: str, top_n: int = 20, erc: str | None = None, kind: str | None = None) -> list[tuple[str, float]]:
        scored: list[tuple[str, float]] = []
        for index, chunk in enumerate(self.chunks):
            if not metadata_matches(chunk, erc=erc, kind=kind):
                continue
            score = self.score(query, index)
            if score > 0:
                scored.append((chunk["id"], score))
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:top_n]


def hashed_embedding(text: str, dimensions: int = 256) -> list[float]:
    """Create a deterministic dense vector from word and bigram features."""
    vector = [0.0] * dimensions
    tokens = tokenize(text)
    features = tokens + [f"{left}_{right}" for left, right in zip(tokens, tokens[1:])]
    for feature in features:
        digest = hashlib.sha256(feature.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:4], "big") % dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[bucket] += sign

    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [value / norm for value in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


class DenseHashIndex:
    """Offline dense retriever based on deterministic feature hashing."""

    def __init__(self, chunks: list[dict[str, Any]], dimensions: int = 256) -> None:
        self.chunks = chunks
        self.dimensions = dimensions
        self.embeddings = [
            hashed_embedding(f"{chunk.get('title', '')} {chunk.get('text', '')}", dimensions=dimensions)
            for chunk in chunks
        ]

    def rank(self, query: str, top_n: int = 20, erc: str | None = None, kind: str | None = None) -> list[tuple[str, float]]:
        query_embedding = hashed_embedding(query, dimensions=self.dimensions)
        scored: list[tuple[str, float]] = []
        for index, chunk in enumerate(self.chunks):
            if not metadata_matches(chunk, erc=erc, kind=kind):
                continue
            score = cosine_similarity(query_embedding, self.embeddings[index])
            if score > 0:
                scored.append((chunk["id"], score))
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:top_n]


def reciprocal_rank_fusion(rankings: list[list[tuple[str, float]]], rrf_k: int = 60) -> list[tuple[str, float]]:
    fused: dict[str, float] = {}
    for ranking in rankings:
        for rank, (chunk_id, _score) in enumerate(ranking, start=1):
            fused[chunk_id] = fused.get(chunk_id, 0.0) + 1.0 / (rrf_k + rank)
    return sorted(fused.items(), key=lambda item: (-item[1], item[0]))


def retrieve(
    query: str,
    k: int = 5,
    erc: str | None = None,
    kind: str | None = None,
    candidate_k: int = 30,
    rrf_k: int = 60,
) -> list[dict[str, Any]]:
    chunks = load_chunks()
    by_id = {chunk["id"]: chunk for chunk in chunks}
    sparse = BM25Index(chunks).rank(query, top_n=candidate_k, erc=erc, kind=kind)
    dense = DenseHashIndex(chunks).rank(query, top_n=candidate_k, erc=erc, kind=kind)
    fused = reciprocal_rank_fusion([sparse, dense], rrf_k=rrf_k)[:k]

    sparse_scores = dict(sparse)
    dense_scores = dict(dense)
    results: list[dict[str, Any]] = []
    for chunk_id, fused_score in fused:
        chunk = dict(by_id[chunk_id])
        chunk["retrieval"] = {
            "mode": "hybrid_bm25_dense_hash_rrf",
            "fused_score": fused_score,
            "sparse_score": sparse_scores.get(chunk_id, 0.0),
            "dense_score": dense_scores.get(chunk_id, 0.0),
        }
        results.append(chunk)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Query the hybrid RAG chunk index.")
    parser.add_argument("query", help="Search query.")
    parser.add_argument("--erc", help="Optional ERC filter, e.g. ERC-20.")
    parser.add_argument("--kind", help="Optional kind filter: erc_standard, vulnerability, threat_pattern, auxiliary.")
    parser.add_argument("-k", type=int, default=5, help="Number of fused results.")
    parser.add_argument("--candidate-k", type=int, default=30, help="Number of sparse/dense candidates before RRF.")
    args = parser.parse_args()

    results = retrieve(args.query, k=args.k, erc=args.erc, kind=args.kind, candidate_k=args.candidate_k)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
