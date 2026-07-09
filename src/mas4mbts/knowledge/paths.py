"""Canonical paths for the MAS4MBTS knowledge base."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
KNOWLEDGE_BASE = PROJECT_ROOT / "knowledge_base"
REGISTRY_DIR = KNOWLEDGE_BASE / "registry"
SEEDS_DIR = KNOWLEDGE_BASE / "seeds"
RAW_DIR = KNOWLEDGE_BASE / "raw"
PROCESSED_DIR = KNOWLEDGE_BASE / "processed"
INDEX_DIR = KNOWLEDGE_BASE / "index"

ERC_PROCESSED_DIR = PROCESSED_DIR / "erc_standards"
VULN_PROCESSED_DIR = PROCESSED_DIR / "vulnerabilities"
THREAT_PATTERN_PROCESSED_DIR = PROCESSED_DIR / "threat_patterns"
EXAMPLES_PROCESSED_DIR = PROCESSED_DIR / "examples"
AUXILIARY_PROCESSED_DIR = PROCESSED_DIR / "auxiliary"
