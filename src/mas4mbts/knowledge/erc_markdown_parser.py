"""Parse raw ERC markdown files into normalized ERC knowledge records."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from src.mas4mbts.knowledge.paths import SEEDS_DIR
from src.mas4mbts.utils.json_io import read_json


FRONT_MATTER_RE = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*", re.DOTALL)
FUNCTION_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.MULTILINE)
EVENT_RE = re.compile(r"event\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.MULTILINE)


def parse_front_matter(markdown: str) -> dict[str, str]:
    match = FRONT_MATTER_RE.match(markdown)
    if not match:
        return {}
    metadata: dict[str, str] = {}
    for line in match.group("body").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata


def strip_front_matter(markdown: str) -> str:
    return FRONT_MATTER_RE.sub("", markdown, count=1)


def extract_section(markdown: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(markdown)
    if not match:
        return ""
    next_heading = re.search(r"^##\s+", markdown[match.end() :], re.MULTILINE)
    if not next_heading:
        return markdown[match.end() :].strip()
    return markdown[match.end() : match.end() + next_heading.start()].strip()


def compact_text(text: str, max_chars: int = 800) -> str:
    compact = " ".join(text.split())
    return compact[:max_chars].rstrip()


def solidity_type_list(raw_args: str) -> str:
    args = []
    for arg in raw_args.split(","):
        arg = arg.strip()
        if not arg:
            continue
        parts = arg.split()
        args.append(parts[0])
    return ",".join(args)


def infer_operation_type(function_name: str) -> str:
    mapping = {
        "totalSupply": "supply_query",
        "balanceOf": "balance_query",
        "transfer": "token_transfer",
        "transferFrom": "delegated_token_transfer",
        "approve": "allowance_management",
        "allowance": "allowance_query",
        "ownerOf": "ownership_query",
        "safeTransferFrom": "safe_transfer",
        "setApprovalForAll": "operator_approval",
        "deposit": "vault_deposit",
        "withdraw": "vault_withdrawal",
        "redeem": "share_redemption",
        "mint": "minting",
        "burn": "burning",
    }
    return mapping.get(function_name, "contract_interaction")


def load_seed_enrichment(record_id: str) -> dict[str, Any]:
    path = SEEDS_DIR / "erc_standards" / f"{record_id}.json"
    if path.exists():
        return read_json(path)
    return {}


def parse_erc_markdown(path: Path) -> dict[str, Any]:
    markdown = path.read_text(encoding="utf-8")
    front_matter = parse_front_matter(markdown)
    body = strip_front_matter(markdown)
    eip_number = str(front_matter.get("eip", "")).strip()
    record_id = f"ERC{eip_number}"
    seed = load_seed_enrichment(record_id)

    abstract = extract_section(body, "Abstract") or extract_section(body, "Simple Summary")
    summary = compact_text(abstract or seed.get("summary", ""))

    functions = []
    seen_functions = set()
    for match in FUNCTION_RE.finditer(body):
        name = match.group(1)
        signature = f"{name}({solidity_type_list(match.group(2))})"
        if signature in seen_functions:
            continue
        seen_functions.add(signature)
        functions.append({"name": name, "signature": signature, "operation_type": infer_operation_type(name)})

    events = []
    seen_events = set()
    for match in EVENT_RE.finditer(body):
        name = match.group(1)
        signature = f"{name}({solidity_type_list(match.group(2))})"
        if signature in seen_events:
            continue
        seen_events.add(signature)
        events.append({"name": name, "signature": signature})

    return {
        "id": record_id,
        "erc": f"ERC-{eip_number}",
        "eip": f"EIP-{eip_number}",
        "title": front_matter.get("title", seed.get("title", "")),
        "status": front_matter.get("status", seed.get("status", "")),
        "category": front_matter.get("category", seed.get("category", "ERC")),
        "source": {
            "source_id": "ethereum_ercs_repo",
            "raw_path": str(path),
            "canonical_url": f"https://eips.ethereum.org/EIPS/eip-{eip_number}",
        },
        "summary": summary,
        "functions": functions or seed.get("functions", []),
        "events": events or seed.get("events", []),
        "assets": seed.get("assets", []),
        "security_properties": seed.get("security_properties", []),
    }
