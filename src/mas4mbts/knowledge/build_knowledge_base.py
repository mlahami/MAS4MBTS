"""Run the reproducible offline knowledge-base build."""

from __future__ import annotations

import argparse

from src.mas4mbts.knowledge.chunker import build_chunks
from src.mas4mbts.knowledge.index_builder import build_index
from src.mas4mbts.knowledge.normalize_raw_owasp import normalize_raw_owasp
from src.mas4mbts.knowledge.normalize_raw_ercs import normalize_raw_ercs
from src.mas4mbts.knowledge.normalize_raw_swc import normalize_raw_swc
from src.mas4mbts.knowledge.seed_ingestor import ingest_all_seeds


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the knowledge base from curated offline seeds.")
    parser.add_argument(
        "--include-raw-ercs",
        action="store_true",
        help="Normalize raw ERC markdown files after seed ingestion and before index building.",
    )
    parser.add_argument("--include-raw-swc", action="store_true", help="Normalize raw SWC markdown files.")
    parser.add_argument("--include-raw-owasp", action="store_true", help="Normalize raw OWASP SCS markdown files.")
    parser.add_argument("--chunk-max-tokens", type=int, default=180, help="Maximum tokens per RAG chunk.")
    parser.add_argument("--chunk-overlap-tokens", type=int, default=35, help="Token overlap between adjacent chunks.")
    args = parser.parse_args()
    status = ingest_all_seeds()
    normalized_raw = normalize_raw_ercs() if args.include_raw_ercs else []
    normalized_swc = normalize_raw_swc() if args.include_raw_swc else []
    normalized_owasp = normalize_raw_owasp() if args.include_raw_owasp else []
    manifest = build_index()
    chunk_manifest = build_chunks(
        max_tokens=args.chunk_max_tokens,
        overlap_tokens=args.chunk_overlap_tokens,
    )
    print(f"Ingested {len(status['items'])} seed records.")
    if args.include_raw_ercs:
        print(f"Normalized {len(normalized_raw)} raw ERC files.")
    if args.include_raw_swc:
        print(f"Normalized {len(normalized_swc)} raw SWC files.")
    if args.include_raw_owasp:
        print(f"Normalized {len(normalized_owasp)} raw OWASP files.")
    print(f"Built index with {manifest['document_count']} documents.")
    print(f"Built chunk index with {chunk_manifest['chunk_count']} chunks.")


if __name__ == "__main__":
    main()
