"""Contract context extraction for ERC threat modeling.

The analyzer is intentionally lightweight and offline. It does not compile
Solidity; it extracts enough structure from Solidity source or ABI files to
feed the ETM threat-model agent.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r"import\s+(?:[^;]*?from\s+)?[\"']([^\"']+)[\"'];")
CONTRACT_RE = re.compile(r"\b(contract|interface|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?\s*{")
FUNCTION_RE = re.compile(r"\bfunction\s+(\w+)\s*\((.*?)\)\s*([^;{]*)([;{])", re.DOTALL)
EVENT_RE = re.compile(r"\bevent\s+(\w+)\s*\((.*?)\)\s*;")
MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+(\w+)\s*\(")
STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+?\)|[A-Za-z_][A-Za-z0-9_<>\[\].]*)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)


VISIBILITIES = {"public", "external", "internal", "private"}
STATE_MUTABILITY = {"view", "pure", "payable"}
FUNCTION_KEYWORDS = VISIBILITIES | STATE_MUTABILITY | {"virtual", "override"}


INTERFACE_IDS = {
    "0x01ffc9a7": "ERC-165",
    "0x36372b07": "ERC-20",
    "0x80ac58cd": "ERC-721",
    "0x5b5e139f": "ERC-721",
    "0x780e9d63": "ERC-721",
    "0xd9b67a26": "ERC-1155",
    "0x0e89341c": "ERC-1155",
    "0x2a55205a": "ERC-2981",
}


STANDARD_SIGNATURES = {
    "ERC-20": {
        "totalSupply",
        "balanceOf",
        "transfer",
        "allowance",
        "approve",
        "transferFrom",
    },
    "ERC-721": {
        "balanceOf",
        "ownerOf",
        "safeTransferFrom",
        "transferFrom",
        "approve",
        "setApprovalForAll",
        "getApproved",
        "isApprovedForAll",
    },
    "ERC-1155": {
        "balanceOf",
        "balanceOfBatch",
        "setApprovalForAll",
        "isApprovedForAll",
        "safeTransferFrom",
        "safeBatchTransferFrom",
        "uri",
    },
    "ERC-4626": {
        "asset",
        "totalAssets",
        "convertToShares",
        "convertToAssets",
        "maxDeposit",
        "previewDeposit",
        "deposit",
        "maxMint",
        "previewMint",
        "mint",
        "maxWithdraw",
        "previewWithdraw",
        "withdraw",
        "maxRedeem",
        "previewRedeem",
        "redeem",
    },
    "ERC-777": {
        "name",
        "symbol",
        "totalSupply",
        "balanceOf",
        "granularity",
        "defaultOperators",
        "isOperatorFor",
        "authorizeOperator",
        "revokeOperator",
        "send",
        "operatorSend",
        "burn",
        "operatorBurn",
    },
}


OPERATION_TYPES = {
    "transfer": "Token transfer",
    "transferFrom": "Delegated token transfer",
    "safeTransferFrom": "Safe token transfer",
    "safeBatchTransferFrom": "Batch token transfer",
    "approve": "Approval management",
    "setApprovalForAll": "Operator approval management",
    "authorizeOperator": "Operator authorization",
    "revokeOperator": "Operator revocation",
    "operatorSend": "Operator token send",
    "operatorBurn": "Operator token burn",
    "send": "Token send",
    "mint": "Token minting",
    "safeMint": "Safe token minting",
    "burn": "Token burning",
    "deposit": "Vault deposit",
    "withdraw": "Vault withdrawal",
    "redeem": "Vault redemption",
    "tokensReceived": "Receive hook",
    "tokensToSend": "Send hook",
}


def strip_comments(source: str) -> str:
    return COMMENT_RE.sub("", source)


def parse_parameter_types(parameters: str) -> list[str]:
    if not parameters.strip():
        return []
    types: list[str] = []
    for raw_parameter in parameters.split(","):
        tokens = [
            token
            for token in raw_parameter.strip().split()
            if token not in {"memory", "calldata", "storage", "indexed", "payable"}
        ]
        if tokens:
            types.append(tokens[0])
    return types


def signature_from_parts(name: str, parameters: str) -> str:
    return f"{name}({','.join(parse_parameter_types(parameters))})"


def extract_contract_block(source: str, contract_name: str | None = None) -> tuple[str, str, list[str]]:
    matches = list(CONTRACT_RE.finditer(source))
    if not matches:
        return "UnknownContract", source, []

    selected = matches[-1]
    if contract_name:
        for match in matches:
            if match.group(2) == contract_name:
                selected = match
                break

    name = selected.group(2)
    inheritance = [
        item.strip().split("(")[0].strip()
        for item in (selected.group(3) or "").split(",")
        if item.strip()
    ]

    start = selected.end()
    depth = 1
    position = start
    while position < len(source) and depth:
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
        position += 1

    return name, source[start : position - 1], inheritance


def extract_functions(contract_body: str) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    for match in FUNCTION_RE.finditer(contract_body):
        name = match.group(1)
        parameters = " ".join(match.group(2).split())
        tail = " ".join(match.group(3).split())
        tokens = tail.replace("(", " ").replace(")", " ").split()
        visibility = next((token for token in tokens if token in VISIBILITIES), "public")
        mutability = next((token for token in tokens if token in STATE_MUTABILITY), "nonpayable")
        modifiers = [
            token
            for token in tokens
            if token not in FUNCTION_KEYWORDS and token != "returns" and not token.startswith("returns")
        ]
        functions.append(
            {
                "name": name,
                "signature": signature_from_parts(name, parameters),
                "visibility": visibility,
                "stateMutability": mutability,
                "modifiers": modifiers,
                "operationType": OPERATION_TYPES.get(name, "Contract interaction"),
            }
        )
    return functions


def extract_events(contract_body: str) -> list[dict[str, str]]:
    return [
        {"name": match.group(1), "signature": signature_from_parts(match.group(1), match.group(2))}
        for match in EVENT_RE.finditer(contract_body)
    ]


def normalize_erc_name(raw: str) -> str | None:
    match = re.search(r"\bI?ERC[-_]?(\d{2,5})\b", raw, flags=re.IGNORECASE)
    if not match:
        return None
    return f"ERC-{match.group(1)}"


def infer_erc_standards(
    source: str,
    imports: list[str],
    inheritance: list[str],
    functions: list[dict[str, Any]],
) -> list[str]:
    standards: list[str] = []

    def add(value: str | None) -> None:
        if value and value not in standards:
            standards.append(value)

    for item in inheritance + imports:
        add(normalize_erc_name(item))

    for interface_id, standard in INTERFACE_IDS.items():
        if interface_id.lower() in source.lower():
            add(standard)

    function_names = {function["name"] for function in functions}
    for standard, required_names in STANDARD_SIGNATURES.items():
        # ERC-20 and ERC-721 overlap; require enough distinctive coverage.
        overlap = function_names & required_names
        threshold = 5 if standard in {"ERC-20", "ERC-721", "ERC-1155"} else 4
        if len(overlap) >= threshold:
            add(standard)

    return standards


def compiler_version_from_source(source: str) -> str:
    match = PRAGMA_RE.search(source)
    return match.group(1).strip() if match else "N/A"


def analyze_solidity_source(source: str, contract_name: str | None = None) -> dict[str, Any]:
    clean_source = strip_comments(source)
    selected_name, contract_body, inheritance = extract_contract_block(clean_source, contract_name=contract_name)
    imports = IMPORT_RE.findall(clean_source)
    functions = extract_functions(contract_body)
    events = extract_events(contract_body)
    standards = infer_erc_standards(clean_source, imports, inheritance, functions)
    modifiers = sorted(set(MODIFIER_DEF_RE.findall(contract_body)))
    state_variables = sorted(set(STATE_VAR_RE.findall(contract_body)))

    return {
        "ercStandard": standards[0] if standards else "UNKNOWN",
        "ercStandards": standards,
        "contractName": selected_name,
        "address": "N/A",
        "compilerVersion": compiler_version_from_source(clean_source),
        "sourceType": "solidity",
        "inheritance": inheritance,
        "imports": imports,
        "functions": functions,
        "events": events,
        "modifiers": modifiers,
        "stateVariables": state_variables,
    }


def abi_entries_from_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("abi"), list):
        return data["abi"]
    if isinstance(data, list):
        return data
    raise ValueError("ABI input must be a JSON array or an object with an 'abi' array.")


def analyze_abi_data(data: Any, contract_name: str = "UnknownContract") -> dict[str, Any]:
    entries = abi_entries_from_json(data)
    functions: list[dict[str, Any]] = []
    events: list[dict[str, str]] = []
    for entry in entries:
        entry_type = entry.get("type", "function")
        name = entry.get("name")
        if not name:
            continue
        inputs = entry.get("inputs", [])
        parameter_types = ",".join(item.get("type", "unknown") for item in inputs)
        if entry_type == "function":
            functions.append(
                {
                    "name": name,
                    "signature": f"{name}({parameter_types})",
                    "visibility": "external",
                    "stateMutability": entry.get("stateMutability", "nonpayable"),
                    "modifiers": [],
                    "operationType": OPERATION_TYPES.get(name, "Contract interaction"),
                }
            )
        elif entry_type == "event":
            events.append({"name": name, "signature": f"{name}({parameter_types})"})

    standards = infer_erc_standards("", [], [], functions)
    return {
        "ercStandard": standards[0] if standards else "UNKNOWN",
        "ercStandards": standards,
        "contractName": contract_name,
        "address": "N/A",
        "compilerVersion": "N/A",
        "sourceType": "abi",
        "inheritance": [],
        "imports": [],
        "functions": functions,
        "events": events,
        "modifiers": [],
        "stateVariables": [],
    }


def analyze_contract_file(path: Path, contract_name: str | None = None) -> dict[str, Any]:
    return analyze_solidity_source(path.read_text(encoding="utf-8"), contract_name=contract_name)


def analyze_abi_file(path: Path, contract_name: str = "UnknownContract") -> dict[str, Any]:
    return analyze_abi_data(json.loads(path.read_text(encoding="utf-8")), contract_name=contract_name)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract a contract context for the ERC threat-model agent.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--solidity", type=Path, help="Path to a Solidity source file.")
    source_group.add_argument("--abi", type=Path, help="Path to an ABI JSON file.")
    parser.add_argument("--contract", help="Optional contract name to select from a Solidity file.")
    parser.add_argument("--output", required=True, type=Path, help="Path where the contract context JSON is written.")
    args = parser.parse_args()

    if args.solidity:
        context = analyze_contract_file(args.solidity, contract_name=args.contract)
    else:
        context = analyze_abi_file(args.abi, contract_name=args.contract or "UnknownContract")

    write_json(args.output, context)
    print(f"Contract context written: {args.output}")


if __name__ == "__main__":
    main()
