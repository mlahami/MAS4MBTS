"""ERC threat model generation agent.

This module is intentionally usable before the full LLM/RAG stack is installed:
it provides a deterministic ERC-20 fallback and a LangGraph-ready structure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.mas4mbts.agents.contract_analyzer import analyze_abi_file, analyze_contract_file
from src.mas4mbts.agents.llm_threat_model_generator import generate_llm_threat_model
from src.mas4mbts.knowledge.hybrid_retriever import retrieve as retrieve_knowledge


PROJECT_ROOT = Path(__file__).resolve().parents[3]
KNOWLEDGE_DIR = PROJECT_ROOT / "data" / "knowledge"
SCHEMA_PATH = PROJECT_ROOT / "src" / "mas4mbts" / "schemas" / "etm_schema.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_knowledge() -> dict[str, Any]:
    return {
        "erc20": (KNOWLEDGE_DIR / "erc20.md").read_text(encoding="utf-8"),
        "owasp": (KNOWLEDGE_DIR / "owasp_threat_modeling.md").read_text(encoding="utf-8"),
        "patterns": load_json(KNOWLEDGE_DIR / "smart_contract_threat_patterns.json"),
    }


def normalize_erc_id(value: str | None) -> str:
    if not value:
        return "ERC-20"
    cleaned = value.upper().replace("_", "-")
    if cleaned.startswith("ERC") and not cleaned.startswith("ERC-"):
        return f"ERC-{cleaned[3:]}"
    return cleaned


def build_retrieval_queries(contract_context: dict[str, Any]) -> list[str]:
    erc = normalize_erc_id(contract_context.get("ercStandard"))
    functions = contract_context.get("functions", [])
    names = [item.get("name", "") for item in functions if item.get("name")]
    operation_types = [item.get("operationType", "") for item in functions if item.get("operationType")]
    base = f"{erc} smart contract threats vulnerabilities mitigations security properties"

    queries = [base]
    if names:
        queries.append(f"{erc} entry points {' '.join(names)}")
    if operation_types:
        queries.append(f"{erc} {' '.join(operation_types)}")
    for name in names:
        queries.append(f"{erc} {name} vulnerability threat mitigation")
    return queries


def retrieve_relevant_knowledge(contract_context: dict[str, Any], k_per_query: int = 4) -> list[dict[str, Any]]:
    erc = normalize_erc_id(contract_context.get("ercStandard"))
    by_id: dict[str, dict[str, Any]] = {}
    for query in build_retrieval_queries(contract_context):
        for item in retrieve_knowledge(query, k=k_per_query, erc=erc):
            by_id.setdefault(item["id"], item)
    return list(by_id.values())


def summarize_knowledge(retrieved_knowledge: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in retrieved_knowledge:
        metadata = item.get("metadata", {})
        summaries.append(
            {
                "id": item.get("id", ""),
                "document_id": item.get("document_id", ""),
                "kind": item.get("kind", ""),
                "title": item.get("title", ""),
                "cwe": metadata.get("cwe", "N/A"),
                "swc": metadata.get("swc", "N/A"),
                "owasp": metadata.get("owasp", "N/A"),
                "source_path": metadata.get("path", ""),
                "retrieval": item.get("retrieval", {}),
            }
        )
    return summaries


def make_source_note(item: dict[str, Any]) -> dict[str, str]:
    metadata = item.get("metadata", {})
    return {
        "chunkId": item.get("id", ""),
        "documentId": item.get("document_id", ""),
        "title": item.get("title", ""),
        "kind": item.get("kind", ""),
        "sourcePath": metadata.get("path", ""),
    }


def compact_erc_id(erc: str) -> str:
    return erc.replace("-", "")


def infer_standard_summary(erc: str, retrieved_knowledge: list[dict[str, Any]] | None = None) -> str:
    if retrieved_knowledge:
        for item in retrieved_knowledge:
            if item.get("kind") == "erc_standard":
                text = item.get("text", "").strip()
                if text:
                    return text[:320]
    return f"Smart contract standard {erc} with contract-specific entry points and state invariants."


def validate_etm_instance(instance: dict[str, Any]) -> None:
    try:
        from jsonschema import validate
    except ImportError as exc:
        validate_minimal_etm_shape(instance)
        return

    validate(instance=instance, schema=load_json(SCHEMA_PATH))


def validate_minimal_etm_shape(instance: dict[str, Any]) -> None:
    """Validate the required ETM sections when jsonschema is unavailable."""
    required_sections = [
        "ercStandard",
        "smartContract",
        "actors",
        "trustLevels",
        "assets",
        "entryPoints",
        "vulnerabilities",
        "threats",
        "countermeasures",
        "securityProperties",
        "testObjectives",
        "relations",
    ]
    missing = [section for section in required_sections if section not in instance]
    if missing:
        raise ValueError(f"Missing required ETM sections: {', '.join(missing)}")

    for section in required_sections[2:]:
        if not isinstance(instance[section], list):
            raise TypeError(f"ETM section must be a list: {section}")

    for section in ["ercStandard", "smartContract"]:
        if not isinstance(instance[section], dict):
            raise TypeError(f"ETM section must be an object: {section}")


COMMON_ACTORS = [
    {"id": "ACT1", "actorName": "Contract owner or admin", "actorType": "Privileged user"},
    {"id": "ACT2", "actorName": "Asset holder", "actorType": "External user"},
    {"id": "ACT3", "actorName": "Approved operator or spender", "actorType": "Delegated user"},
    {"id": "ACT4", "actorName": "Attacker", "actorType": "Malicious external user"},
]


COMMON_TRUST_LEVELS = [
    {"id": "TL1", "levelName": "Trusted administrator", "permissions": ["manage privileged functions"]},
    {"id": "TL2", "levelName": "Asset holder", "permissions": ["transfer owned assets", "approve delegated access"]},
    {"id": "TL3", "levelName": "Approved delegate", "permissions": ["operate within granted approvals"]},
    {"id": "TL4", "levelName": "Untrusted external user", "permissions": ["call public functions"]},
]


ERC_PROFILES: dict[str, dict[str, Any]] = {
    "ERC-20": {
        "standard": {
            "id": "ERC20",
            "name": "ERC-20",
            "version": "EIP-20",
            "description": "Fungible token standard defining transfer, approval, and allowance mechanisms.",
        },
        "assets": [
            {"assetName": "Token balances", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Token allowances", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Total supply", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Contract ownership or roles", "assetType": "Access control state", "criticality": "High"},
        ],
        "threats": [
            {
                "name": "Approval Race Condition",
                "description": "A spender exploits transaction ordering around approve() to consume more allowance than intended.",
                "stride": "Tampering",
                "triggers": ["approve"],
                "assets": ["Token allowances"],
                "vulnerability": {
                    "vulnerabilityName": "Transaction-ordering dependent allowance update",
                    "category": "Transaction ordering",
                    "severity": "Medium",
                    "CWE": "CWE-362",
                    "SWC": "SWC-114",
                },
                "countermeasure": {
                    "countermeasureName": "Safe allowance update pattern",
                    "description": "Use increase/decrease allowance or require resetting allowance to zero before changing it.",
                },
                "securityProperty": {
                    "propertyName": "Allowance consistency",
                    "description": "Allowance updates must not allow unintended double spending.",
                },
                "testObjective": {
                    "objectiveName": "Allowance race-condition test",
                    "expectedBehavior": "approve() cannot be exploited to spend both old and new allowances.",
                },
            },
            {
                "name": "Balance or Supply Invariant Violation",
                "description": "A token operation incorrectly updates balances or total supply.",
                "stride": "Tampering",
                "default": True,
                "triggers": ["transfer", "transferFrom", "mint", "burn"],
                "assets": ["Token balances", "Total supply"],
                "vulnerability": {
                    "vulnerabilityName": "Incorrect accounting",
                    "category": "Business logic",
                    "severity": "High",
                    "CWE": "CWE-682",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Accounting invariant checks",
                    "description": "Preserve balance and total-supply invariants across transfer, mint, and burn operations.",
                },
                "securityProperty": {
                    "propertyName": "Token accounting integrity",
                    "description": "Token operations must preserve balances and total-supply invariants.",
                },
                "testObjective": {
                    "objectiveName": "Accounting invariant test",
                    "expectedBehavior": "transfer, mint, and burn operations preserve expected token accounting.",
                },
            },
            {
                "name": "Unauthorized Minting",
                "description": "An unauthorized actor calls mint() to create tokens.",
                "stride": "Elevation of Privilege",
                "triggers": ["mint"],
                "assets": ["Total supply", "Contract ownership or roles"],
                "vulnerability": {
                    "vulnerabilityName": "Missing access control",
                    "category": "Authorization",
                    "severity": "High",
                    "CWE": "CWE-284",
                    "SWC": "SWC-105",
                },
                "countermeasure": {
                    "countermeasureName": "Role-based access control",
                    "description": "Restrict minting to the owner or an authorized minter role.",
                },
                "securityProperty": {
                    "propertyName": "Mint authorization",
                    "description": "Only authorized actors can mint new tokens.",
                },
                "testObjective": {
                    "objectiveName": "Unauthorized minting test",
                    "expectedBehavior": "mint() reverts when called by an unauthorized actor.",
                },
            },
            {
                "name": "Reentrancy on Withdraw",
                "description": "A malicious receiver re-enters withdraw() before state is finalized.",
                "stride": "Tampering",
                "triggers": ["withdraw"],
                "assets": ["Token balances"],
                "vulnerability": {
                    "vulnerabilityName": "Reentrancy",
                    "category": "External call",
                    "severity": "High",
                    "CWE": "CWE-841",
                    "SWC": "SWC-107",
                },
                "countermeasure": {
                    "countermeasureName": "Checks-effects-interactions or reentrancy guard",
                    "description": "Update state before external calls and protect sensitive functions with a reentrancy guard.",
                },
                "securityProperty": {
                    "propertyName": "Reentrancy resistance",
                    "description": "External callbacks must not allow repeated consumption of the same state.",
                },
                "testObjective": {
                    "objectiveName": "Reentrancy resistance test",
                    "expectedBehavior": "withdraw() cannot be re-entered to drain funds.",
                },
            },
        ],
    },
    "ERC-721": {
        "standard": {
            "id": "ERC721",
            "name": "ERC-721",
            "version": "EIP-721",
            "description": "Non-fungible token standard defining unique token ownership, approvals, and transfers.",
        },
        "assets": [
            {"assetName": "NFT ownership records", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Token approvals", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Operator approvals", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Token metadata URI", "assetType": "Metadata", "criticality": "Medium"},
            {"assetName": "Token uniqueness", "assetType": "Business invariant", "criticality": "High"},
        ],
        "threats": [
            {
                "name": "Unauthorized NFT Transfer",
                "description": "An attacker transfers a token without being the owner, approved address, or authorized operator.",
                "stride": "Elevation of Privilege",
                "default": True,
                "triggers": ["transferFrom", "safeTransferFrom"],
                "assets": ["NFT ownership records", "Token approvals", "Operator approvals"],
                "vulnerability": {
                    "vulnerabilityName": "Improper NFT transfer authorization",
                    "category": "Authorization",
                    "severity": "High",
                    "CWE": "CWE-284",
                    "SWC": "SWC-105",
                },
                "countermeasure": {
                    "countermeasureName": "Owner and approval authorization checks",
                    "description": "Require token ownership, token approval, or operator approval before transfer.",
                },
                "securityProperty": {
                    "propertyName": "NFT transfer authorization",
                    "description": "Only owners and authorized delegates can transfer a token.",
                },
                "testObjective": {
                    "objectiveName": "Unauthorized NFT transfer test",
                    "expectedBehavior": "transferFrom and safeTransferFrom revert for unauthorized callers.",
                },
            },
            {
                "name": "Operator Approval Abuse",
                "description": "A malicious or compromised operator abuses setApprovalForAll to move many tokens.",
                "stride": "Elevation of Privilege",
                "triggers": ["setApprovalForAll"],
                "assets": ["Operator approvals", "NFT ownership records"],
                "vulnerability": {
                    "vulnerabilityName": "Overbroad operator approval",
                    "category": "Authorization",
                    "severity": "Medium",
                    "CWE": "CWE-863",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Explicit operator approval controls",
                    "description": "Make operator approval explicit, revocable, and visible to token holders.",
                },
                "securityProperty": {
                    "propertyName": "Operator delegation safety",
                    "description": "Delegated operators must not exceed the holder's granted authority.",
                },
                "testObjective": {
                    "objectiveName": "Operator approval abuse test",
                    "expectedBehavior": "Only approved operators can transfer holder tokens, and revocation is enforced.",
                },
            },
            {
                "name": "Duplicate or Unauthorized Minting",
                "description": "A token is minted twice or minted by an unauthorized caller.",
                "stride": "Tampering",
                "triggers": ["mint", "safeMint"],
                "assets": ["Token uniqueness", "NFT ownership records"],
                "vulnerability": {
                    "vulnerabilityName": "Broken NFT minting invariant",
                    "category": "Business logic",
                    "severity": "High",
                    "CWE": "CWE-284",
                    "SWC": "SWC-105",
                },
                "countermeasure": {
                    "countermeasureName": "Mint authorization and token existence checks",
                    "description": "Restrict minting and reject token IDs that already exist.",
                },
                "securityProperty": {
                    "propertyName": "NFT uniqueness and mint authorization",
                    "description": "Each token ID is unique and can only be minted by authorized actors.",
                },
                "testObjective": {
                    "objectiveName": "NFT minting invariant test",
                    "expectedBehavior": "Unauthorized minting and duplicate token IDs are rejected.",
                },
            },
            {
                "name": "Unsafe Receiver Handling",
                "description": "safeTransferFrom incorrectly handles receiver callbacks or accepts unsafe receivers.",
                "stride": "Tampering",
                "triggers": ["safeTransferFrom"],
                "assets": ["NFT ownership records"],
                "vulnerability": {
                    "vulnerabilityName": "Unsafe ERC721 receiver interaction",
                    "category": "External call",
                    "severity": "Medium",
                    "CWE": "CWE-841",
                    "SWC": "SWC-107",
                },
                "countermeasure": {
                    "countermeasureName": "ERC721 receiver callback validation",
                    "description": "Require the receiver magic value and avoid unsafe state transitions around callbacks.",
                },
                "securityProperty": {
                    "propertyName": "Safe NFT receiver compatibility",
                    "description": "Safe transfers only complete when the receiver accepts ERC-721 tokens.",
                },
                "testObjective": {
                    "objectiveName": "Safe receiver handling test",
                    "expectedBehavior": "safeTransferFrom reverts for contracts that do not implement the receiver callback.",
                },
            },
        ],
    },
    "ERC-1155": {
        "standard": {
            "id": "ERC1155",
            "name": "ERC-1155",
            "version": "EIP-1155",
            "description": "Multi-token standard supporting fungible, semi-fungible, and non-fungible token IDs.",
        },
        "assets": [
            {"assetName": "Per-token balances", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Batch transfer accounting", "assetType": "Business invariant", "criticality": "High"},
            {"assetName": "Operator approvals", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Token ID metadata", "assetType": "Metadata", "criticality": "Medium"},
        ],
        "threats": [
            {
                "name": "Unauthorized Multi-token Transfer",
                "description": "An attacker transfers ERC-1155 balances without owner or operator authorization.",
                "stride": "Elevation of Privilege",
                "default": True,
                "triggers": ["safeTransferFrom", "safeBatchTransferFrom"],
                "assets": ["Per-token balances", "Operator approvals"],
                "vulnerability": {
                    "vulnerabilityName": "Improper ERC1155 transfer authorization",
                    "category": "Authorization",
                    "severity": "High",
                    "CWE": "CWE-284",
                    "SWC": "SWC-105",
                },
                "countermeasure": {
                    "countermeasureName": "Owner or operator authorization checks",
                    "description": "Require the caller to be the owner or an approved operator for transfers.",
                },
                "securityProperty": {
                    "propertyName": "ERC1155 transfer authorization",
                    "description": "Only holders and approved operators can transfer token balances.",
                },
                "testObjective": {
                    "objectiveName": "Unauthorized ERC1155 transfer test",
                    "expectedBehavior": "Transfers revert for callers without holder or operator authority.",
                },
            },
            {
                "name": "Batch Accounting Mismatch",
                "description": "Batch operations update token IDs or balances inconsistently.",
                "stride": "Tampering",
                "triggers": ["safeBatchTransferFrom", "mintBatch", "burnBatch"],
                "assets": ["Batch transfer accounting", "Per-token balances"],
                "vulnerability": {
                    "vulnerabilityName": "Incorrect ERC1155 batch accounting",
                    "category": "Business logic",
                    "severity": "High",
                    "CWE": "CWE-682",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Batch length and balance invariant checks",
                    "description": "Validate matching IDs and amounts arrays and preserve balances per token ID.",
                },
                "securityProperty": {
                    "propertyName": "Batch accounting integrity",
                    "description": "Batch updates preserve per-token accounting and array consistency.",
                },
                "testObjective": {
                    "objectiveName": "ERC1155 batch accounting test",
                    "expectedBehavior": "Mismatched arrays and balance-breaking batch operations revert.",
                },
            },
        ],
    },
    "ERC-4626": {
        "standard": {
            "id": "ERC4626",
            "name": "ERC-4626",
            "version": "EIP-4626",
            "description": "Tokenized vault standard defining deposits, withdrawals, shares, and asset conversion.",
        },
        "assets": [
            {"assetName": "Vault assets", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Vault shares", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Share price or exchange rate", "assetType": "Business invariant", "criticality": "High"},
            {"assetName": "Deposit and withdrawal limits", "assetType": "Policy", "criticality": "Medium"},
        ],
        "threats": [
            {
                "name": "Share Price Manipulation",
                "description": "An attacker manipulates vault accounting or donations to skew asset/share conversion.",
                "stride": "Tampering",
                "default": True,
                "triggers": ["deposit", "mint", "withdraw", "redeem"],
                "assets": ["Share price or exchange rate", "Vault assets", "Vault shares"],
                "vulnerability": {
                    "vulnerabilityName": "Incorrect vault share accounting",
                    "category": "Business logic",
                    "severity": "High",
                    "CWE": "CWE-682",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Vault conversion invariant checks",
                    "description": "Preserve asset/share conversion invariants across deposits, mints, withdrawals, and redeems.",
                },
                "securityProperty": {
                    "propertyName": "Vault accounting integrity",
                    "description": "Share and asset accounting reflects fair vault ownership.",
                },
                "testObjective": {
                    "objectiveName": "Vault share manipulation test",
                    "expectedBehavior": "Conversion functions and state-changing vault operations cannot be manipulated for unfair shares.",
                },
            },
            {
                "name": "Withdrawal Limit Bypass",
                "description": "A caller withdraws or redeems more assets than allowed by vault limits or share ownership.",
                "stride": "Elevation of Privilege",
                "triggers": ["withdraw", "redeem"],
                "assets": ["Vault assets", "Deposit and withdrawal limits"],
                "vulnerability": {
                    "vulnerabilityName": "Improper withdrawal authorization or limit enforcement",
                    "category": "Authorization",
                    "severity": "High",
                    "CWE": "CWE-863",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Withdrawal authorization and max limit checks",
                    "description": "Enforce owner, allowance, maxWithdraw, and maxRedeem constraints.",
                },
                "securityProperty": {
                    "propertyName": "Vault withdrawal safety",
                    "description": "Withdrawals and redemptions cannot exceed authorized shares or vault limits.",
                },
                "testObjective": {
                    "objectiveName": "Vault withdrawal limit test",
                    "expectedBehavior": "withdraw and redeem revert when caller authority, shares, or max limits are insufficient.",
                },
            },
        ],
    },
}


def build_generic_erc_profile(erc: str, retrieved_knowledge: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    standard_id = compact_erc_id(erc)
    return {
        "standard": {
            "id": standard_id,
            "name": erc,
            "version": f"EIP-{standard_id[3:]}" if standard_id.startswith("ERC") else "N/A",
            "description": infer_standard_summary(erc, retrieved_knowledge),
        },
        "assets": [
            {"assetName": "Standard-specific balances or ownership state", "assetType": "Contract state", "criticality": "High"},
            {"assetName": "Delegated permissions or approvals", "assetType": "Access control state", "criticality": "High"},
            {"assetName": "Supply or accounting invariants", "assetType": "Business invariant", "criticality": "High"},
            {"assetName": "Metadata or configuration", "assetType": "Metadata", "criticality": "Medium"},
            {"assetName": "External interaction state", "assetType": "Integration boundary", "criticality": "Medium"},
        ],
        "threats": [
            {
                "name": "Unauthorized Standard Operation",
                "description": "An unauthorized caller executes a privileged or ownership-sensitive standard operation.",
                "stride": "Elevation of Privilege",
                "default": True,
                "triggers": [
                    "approve",
                    "setApprovalForAll",
                    "authorizeOperator",
                    "operatorSend",
                    "operatorBurn",
                    "mint",
                    "safeMint",
                    "upgrade",
                ],
                "assets": ["Delegated permissions or approvals", "Standard-specific balances or ownership state"],
                "vulnerability": {
                    "vulnerabilityName": "Improper standard operation authorization",
                    "category": "Authorization",
                    "severity": "High",
                    "CWE": "CWE-284",
                    "SWC": "SWC-105",
                },
                "countermeasure": {
                    "countermeasureName": "Standard-aware authorization checks",
                    "description": "Enforce owner, role, operator, allowance, or standard-specific authorization preconditions.",
                },
                "securityProperty": {
                    "propertyName": "Authorized standard operations",
                    "description": "Sensitive standard operations can only be executed by authorized actors.",
                },
                "testObjective": {
                    "objectiveName": "Unauthorized standard operation test",
                    "expectedBehavior": "Sensitive entry points revert for callers lacking standard-specific authority.",
                },
            },
            {
                "name": "Standard Accounting Invariant Violation",
                "description": "A state transition violates balances, ownership, supply, share, or token-ID invariants.",
                "stride": "Tampering",
                "default": True,
                "triggers": [
                    "transfer",
                    "transferFrom",
                    "safeTransferFrom",
                    "safeBatchTransferFrom",
                    "send",
                    "operatorSend",
                    "deposit",
                    "withdraw",
                    "redeem",
                    "mint",
                    "burn",
                ],
                "assets": ["Standard-specific balances or ownership state", "Supply or accounting invariants"],
                "vulnerability": {
                    "vulnerabilityName": "Incorrect standard accounting",
                    "category": "Business logic",
                    "severity": "High",
                    "CWE": "CWE-682",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Standard invariant checks",
                    "description": "Validate preconditions and assert post-state invariants for each state-changing operation.",
                },
                "securityProperty": {
                    "propertyName": "Standard accounting integrity",
                    "description": "State transitions preserve standard-specific accounting and ownership invariants.",
                },
                "testObjective": {
                    "objectiveName": "Standard accounting invariant test",
                    "expectedBehavior": "State-changing operations preserve balances, ownership, supply, and related invariants.",
                },
            },
            {
                "name": "Unsafe External Callback or Receiver Interaction",
                "description": "A standard operation invokes an external receiver, hook, or callback in an unsafe state.",
                "stride": "Tampering",
                "triggers": [
                    "safeTransferFrom",
                    "safeBatchTransferFrom",
                    "send",
                    "operatorSend",
                    "tokensToSend",
                    "tokensReceived",
                    "onERC721Received",
                    "onERC1155Received",
                    "onERC1155BatchReceived",
                    "withdraw",
                ],
                "assets": ["External interaction state", "Standard-specific balances or ownership state"],
                "vulnerability": {
                    "vulnerabilityName": "Unsafe standard callback interaction",
                    "category": "External call",
                    "severity": "High",
                    "CWE": "CWE-841",
                    "SWC": "SWC-107",
                },
                "countermeasure": {
                    "countermeasureName": "Callback-safe state transition",
                    "description": "Use checks-effects-interactions, reentrancy protection, and receiver magic-value validation where applicable.",
                },
                "securityProperty": {
                    "propertyName": "Callback safety",
                    "description": "External callbacks cannot observe or exploit inconsistent intermediate state.",
                },
                "testObjective": {
                    "objectiveName": "Unsafe callback interaction test",
                    "expectedBehavior": "Receiver hooks and callbacks cannot re-enter or bypass standard safety checks.",
                },
            },
            {
                "name": "Metadata or Configuration Integrity Violation",
                "description": "An attacker changes or exploits standard metadata, configuration, or registry-dependent values.",
                "stride": "Tampering",
                "triggers": [
                    "setURI",
                    "setBaseURI",
                    "tokenURI",
                    "uri",
                    "name",
                    "symbol",
                    "defaultOperators",
                ],
                "assets": ["Metadata or configuration"],
                "vulnerability": {
                    "vulnerabilityName": "Improper metadata or configuration control",
                    "category": "Configuration",
                    "severity": "Medium",
                    "CWE": "CWE-732",
                    "SWC": "N/A",
                },
                "countermeasure": {
                    "countermeasureName": "Metadata and configuration access control",
                    "description": "Restrict mutable metadata and configuration changes to authorized actors and validate derived values.",
                },
                "securityProperty": {
                    "propertyName": "Metadata integrity",
                    "description": "Metadata and configuration remain accurate and cannot be modified by unauthorized actors.",
                },
                "testObjective": {
                    "objectiveName": "Metadata integrity test",
                    "expectedBehavior": "Unauthorized metadata or configuration changes are rejected.",
                },
            },
        ],
    }


def get_erc_profile(erc: str, retrieved_knowledge: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return ERC_PROFILES.get(erc, build_generic_erc_profile(erc, retrieved_knowledge))


def build_threat_model(
    contract_context: dict[str, Any],
    retrieved_knowledge: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an ETM-compliant threat model from an ERC-specific profile."""
    contract_name = contract_context.get("contractName", "SimpleERC20Token")
    compiler_version = contract_context.get("compilerVersion", "0.8.x")
    address = contract_context.get("address", "N/A")
    functions = contract_context.get("functions", [])
    function_names = {item.get("name", "") for item in functions if item.get("name")}
    erc = normalize_erc_id(contract_context.get("ercStandard"))
    profile = get_erc_profile(erc, retrieved_knowledge)

    entry_points = [
        {
            "id": f"EP{index}",
            "functionName": item.get("signature", item.get("name", "unknown")),
            "visibility": item.get("visibility", "public"),
            "operationType": item.get("operationType", infer_operation_type(item.get("name", ""))),
        }
        for index, item in enumerate(functions, start=1)
    ]

    assets = [{"id": f"A{index}", **asset} for index, asset in enumerate(profile["assets"], start=1)]
    asset_ids_by_name = {asset["assetName"]: asset["id"] for asset in assets}

    selected_templates = [
        template
        for template in profile["threats"]
        if template.get("default") or any(trigger in function_names for trigger in template.get("triggers", []))
    ]

    threats: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    countermeasures: list[dict[str, Any]] = []
    security_properties: list[dict[str, Any]] = []
    test_objectives: list[dict[str, Any]] = []
    selected_threats: list[dict[str, Any]] = []

    for index, template in enumerate(selected_templates, start=1):
        threat = {
            "id": f"T{index}",
            "threatName": template["name"],
            "description": template["description"],
            "STRIDECategory": template["stride"],
        }
        vulnerability = {"id": f"V{index}", **template["vulnerability"]}
        countermeasure = {"id": f"CM{index}", **template["countermeasure"]}
        security_property = {"id": f"SP{index}", **template["securityProperty"]}
        test_objective = {"id": f"TO{index}", **template["testObjective"]}

        threats.append(threat)
        vulnerabilities.append(vulnerability)
        countermeasures.append(countermeasure)
        security_properties.append(security_property)
        test_objectives.append(test_objective)
        selected_threats.append(
            {
                "template": template,
                "threat": threat,
                "vulnerability": vulnerability,
                "countermeasure": countermeasure,
                "securityProperty": security_property,
                "testObjective": test_objective,
                "assetIds": [asset_ids_by_name[name] for name in template.get("assets", []) if name in asset_ids_by_name],
            }
        )

    model = {
        "ercStandard": profile["standard"],
        "smartContract": {
            "id": "SC1",
            "contractName": contract_name,
            "address": address,
            "compilerVersion": compiler_version,
        },
        "actors": COMMON_ACTORS,
        "trustLevels": COMMON_TRUST_LEVELS,
        "assets": assets,
        "entryPoints": entry_points,
        "vulnerabilities": vulnerabilities,
        "threats": threats,
        "countermeasures": countermeasures,
        "securityProperties": security_properties,
        "testObjectives": test_objectives,
        "relations": build_relations(profile["standard"]["id"], entry_points, selected_threats),
    }

    if retrieved_knowledge:
        enrich_model_with_knowledge(model, retrieved_knowledge)

    return model


def build_erc20_threat_model(
    contract_context: dict[str, Any],
    retrieved_knowledge: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper for the old ERC-20 entry point."""
    contract_context = dict(contract_context)
    contract_context["ercStandard"] = "ERC-20"
    return build_threat_model(contract_context, retrieved_knowledge=retrieved_knowledge)


def infer_operation_type(function_name: str) -> str:
    mapping = {
        "transfer": "Token transfer",
        "transferFrom": "Delegated token transfer",
        "approve": "Allowance management",
        "mint": "Token minting",
        "safeMint": "Safe token minting",
        "burn": "Token burning",
        "withdraw": "Value withdrawal",
        "safeTransferFrom": "Safe token transfer",
        "safeBatchTransferFrom": "Batch token transfer",
        "setApprovalForAll": "Operator approval management",
        "mintBatch": "Batch token minting",
        "burnBatch": "Batch token burning",
        "deposit": "Vault deposit",
        "redeem": "Vault share redemption",
    }
    return mapping.get(function_name, "Contract interaction")


def build_relations(
    standard_id: str,
    entry_points: list[dict[str, Any]],
    selected_threats: list[dict[str, Any]],
) -> list[dict[str, str]]:
    relations = [{"type": "defines", "from": standard_id, "to": "SC1"}]
    relations.extend({"type": "exposes", "from": "SC1", "to": ep["id"]} for ep in entry_points)

    entry_by_name = {ep["functionName"].split("(")[0]: ep["id"] for ep in entry_points}
    for selected in selected_threats:
        template = selected["template"]
        threat = selected["threat"]
        source = "SC1"
        for trigger in template.get("triggers", []):
            if trigger in entry_by_name:
                source = entry_by_name[trigger]
                break

        relations.append({"type": "mayTrigger", "from": source, "to": threat["id"]})
        relations.extend({"type": "targets", "from": threat["id"], "to": asset_id} for asset_id in selected["assetIds"])
        relations.extend(
            [
                {"type": "exploits", "from": threat["id"], "to": selected["vulnerability"]["id"]},
                {"type": "mitigatedBy", "from": threat["id"], "to": selected["countermeasure"]["id"]},
                {"type": "violates", "from": threat["id"], "to": selected["securityProperty"]["id"]},
                {"type": "validatedBy", "from": threat["id"], "to": selected["testObjective"]["id"]},
            ]
        )

    return relations


def text_matches_any(text: str, needles: list[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def append_source_note(target: dict[str, Any], source: dict[str, Any]) -> None:
    note = make_source_note(source)
    existing = target.setdefault("knowledgeSources", [])
    if note["chunkId"] and all(item.get("chunkId") != note["chunkId"] for item in existing):
        existing.append(note)


def enrich_model_with_knowledge(model: dict[str, Any], retrieved_knowledge: list[dict[str, Any]]) -> None:
    """Attach traceable KB evidence to ETM elements selected by the deterministic builder."""
    model["knowledgeSources"] = summarize_knowledge(retrieved_knowledge)

    for source in retrieved_knowledge:
        source_text = f"{source.get('title', '')} {source.get('text', '')}"
        metadata = source.get("metadata", {})
        source_text = f"{source_text} {metadata.get('swc', '')} {metadata.get('cwe', '')} {metadata.get('owasp', '')}"

        for threat in model["threats"]:
            keywords = [threat["threatName"], threat["description"], threat["STRIDECategory"]]
            if text_matches_any(source_text, keywords):
                append_source_note(threat, source)

        for vulnerability in model["vulnerabilities"]:
            keywords = [
                vulnerability["vulnerabilityName"],
                vulnerability["category"],
                vulnerability["CWE"],
                vulnerability["SWC"],
            ]
            if text_matches_any(source_text, keywords):
                append_source_note(vulnerability, source)

        for countermeasure in model["countermeasures"]:
            if text_matches_any(source_text, [countermeasure["countermeasureName"], countermeasure["description"]]):
                append_source_note(countermeasure, source)

        for objective in model["testObjectives"]:
            if text_matches_any(source_text, [objective["objectiveName"], objective["expectedBehavior"]]):
                append_source_note(objective, source)


def repair_minimal_etm(model: dict[str, Any]) -> dict[str, Any]:
    """Fill required ETM containers if a future generator omits them."""
    for key in [
        "actors",
        "trustLevels",
        "assets",
        "entryPoints",
        "vulnerabilities",
        "threats",
        "countermeasures",
        "securityProperties",
        "testObjectives",
        "relations",
    ]:
        model.setdefault(key, [])
    model.setdefault(
        "ercStandard",
        {"id": "UNKNOWN", "name": "Unknown ERC", "version": "N/A", "description": "Not provided."},
    )
    model.setdefault(
        "smartContract",
        {"id": "SC1", "contractName": "UnknownContract", "address": "N/A", "compilerVersion": "N/A"},
    )
    return model


def run_agent_pipeline(
    contract_context: dict[str, Any],
    validate: bool = True,
    generation_mode: str = "deterministic",
) -> dict[str, Any]:
    if generation_mode not in {"deterministic", "llm"}:
        raise ValueError(f"Unsupported generation mode: {generation_mode}")

    state: dict[str, Any] = {
        "generation_mode": generation_mode,
        "contract_context": contract_context,
        "retrieved_knowledge": [],
        "deterministic_baseline": {},
        "llm_metadata": {},
        "draft_threat_model": {},
        "validation_errors": [],
        "final_threat_model": {},
    }

    try:
        state["retrieved_knowledge"] = retrieve_relevant_knowledge(contract_context)
    except FileNotFoundError as exc:
        state["validation_errors"].append(f"Knowledge retrieval skipped: {exc}")

    state["deterministic_baseline"] = build_threat_model(
        contract_context,
        retrieved_knowledge=state["retrieved_knowledge"],
    )
    if generation_mode == "llm":
        state["draft_threat_model"], state["llm_metadata"] = generate_llm_threat_model(
            contract_context,
            state["retrieved_knowledge"],
            state["deterministic_baseline"],
        )
        if state["retrieved_knowledge"]:
            enrich_model_with_knowledge(state["draft_threat_model"], state["retrieved_knowledge"])
    else:
        state["draft_threat_model"] = state["deterministic_baseline"]

    state["final_threat_model"] = repair_minimal_etm(dict(state["draft_threat_model"]))

    if validate:
        try:
            validate_etm_instance(state["final_threat_model"])
        except Exception as exc:
            state["validation_errors"].append(str(exc))
            state["final_threat_model"] = repair_minimal_etm(state["final_threat_model"])
            validate_etm_instance(state["final_threat_model"])

    return state


def run_agent(
    input_path: Path,
    output_path: Path,
    validate: bool = True,
    state_output_path: Path | None = None,
    generation_mode: str = "deterministic",
) -> dict[str, Any]:
    contract_context = load_json(input_path)
    _knowledge = load_knowledge()

    state = run_agent_pipeline(contract_context, validate=validate, generation_mode=generation_mode)
    model = state["final_threat_model"]

    write_json(output_path, model)
    if state_output_path:
        write_json(state_output_path, state)
    return model


def run_agent_from_context(
    contract_context: dict[str, Any],
    output_path: Path,
    validate: bool = True,
    state_output_path: Path | None = None,
    generation_mode: str = "deterministic",
) -> dict[str, Any]:
    _knowledge = load_knowledge()

    state = run_agent_pipeline(contract_context, validate=validate, generation_mode=generation_mode)
    model = state["final_threat_model"]

    write_json(output_path, model)
    if state_output_path:
        write_json(state_output_path, state)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an ETM-compliant ERC threat model.")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--input", type=Path, help="Path to a prepared contract context JSON file.")
    source_group.add_argument("--solidity", type=Path, help="Path to a Solidity source file to analyze.")
    source_group.add_argument("--abi", type=Path, help="Path to an ABI JSON file to analyze.")
    parser.add_argument("--contract", help="Optional contract name for Solidity or ABI analysis.")
    parser.add_argument("--output", required=True, type=Path, help="Path where the generated threat model is written.")
    parser.add_argument("--state-output", type=Path, help="Optional path where the agent state is written.")
    parser.add_argument(
        "--mode",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="Generation mode: deterministic baseline or Groq LLM-assisted generator.",
    )
    parser.add_argument("--no-validate", action="store_true", help="Skip JSON Schema validation.")
    args = parser.parse_args()

    if args.input:
        run_agent(
            args.input,
            args.output,
            validate=not args.no_validate,
            state_output_path=args.state_output,
            generation_mode=args.mode,
        )
    elif args.solidity:
        context = analyze_contract_file(args.solidity, contract_name=args.contract)
        run_agent_from_context(
            context,
            args.output,
            validate=not args.no_validate,
            state_output_path=args.state_output,
            generation_mode=args.mode,
        )
    else:
        context = analyze_abi_file(args.abi, contract_name=args.contract or "UnknownContract")
        run_agent_from_context(
            context,
            args.output,
            validate=not args.no_validate,
            state_output_path=args.state_output,
            generation_mode=args.mode,
        )

    print(f"Threat model generated: {args.output}")
    if args.state_output:
        print(f"Agent state written: {args.state_output}")


if __name__ == "__main__":
    main()
