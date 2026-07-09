"""LLM-assisted ETM threat model generation."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_PATH = PROJECT_ROOT / ".env"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_dotenv(path: Path = ENV_PATH) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def trim_text(text: str, max_chars: int = 1000) -> str:
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}..."


def compact_knowledge(retrieved_knowledge: list[dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in retrieved_knowledge[:limit]:
        metadata = item.get("metadata", {})
        compact.append(
            {
                "id": item.get("id", ""),
                "document_id": item.get("document_id", ""),
                "kind": item.get("kind", ""),
                "title": item.get("title", ""),
                "text": trim_text(item.get("text", ""), max_chars=500),
                "cwe": metadata.get("cwe", "N/A"),
                "swc": metadata.get("swc", "N/A"),
                "owasp": metadata.get("owasp", "N/A"),
                "source_path": metadata.get("path", ""),
            }
        )
    return compact


def strip_knowledge_sources(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: strip_knowledge_sources(item) for key, item in value.items() if key != "knowledgeSources"}
    if isinstance(value, list):
        return [strip_knowledge_sources(item) for item in value]
    return value


def etm_shape_summary() -> dict[str, Any]:
    return {
        "required_top_level_sections": [
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
        ],
        "required_ids": {
            "ercStandard": ["id", "name", "version", "description"],
            "smartContract": ["id", "contractName", "address", "compilerVersion"],
            "actor": ["id", "actorName", "actorType"],
            "trustLevel": ["id", "levelName", "permissions"],
            "asset": ["id", "assetName", "assetType", "criticality"],
            "entryPoint": ["id", "functionName", "visibility", "operationType"],
            "vulnerability": ["id", "vulnerabilityName", "category", "severity", "CWE", "SWC"],
            "threat": ["id", "threatName", "description", "STRIDECategory"],
            "countermeasure": ["id", "countermeasureName", "description"],
            "securityProperty": ["id", "propertyName", "description"],
            "testObjective": ["id", "objectiveName", "expectedBehavior"],
            "relation": ["type", "from", "to"],
        },
        "required_threat_relations": ["targets", "exploits", "mitigatedBy", "violates", "validatedBy"],
    }


def strip_code_fence(content: str) -> str:
    stripped = content.strip()
    match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, flags=re.DOTALL)
    return match.group(1).strip() if match else stripped


def parse_json_response(content: str) -> dict[str, Any]:
    return json.loads(strip_code_fence(content))


def build_prompt_payload(
    contract_context: dict[str, Any],
    retrieved_knowledge: list[dict[str, Any]],
    deterministic_model: dict[str, Any],
) -> dict[str, Any]:
    return {
        "contract_context": contract_context,
        "retrieved_knowledge": compact_knowledge(retrieved_knowledge),
        "deterministic_baseline": strip_knowledge_sources(deterministic_model),
        "etm_shape": etm_shape_summary(),
    }


def build_messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    system = (
        "You are a smart contract security threat modeling agent. "
        "Generate one ETM-compliant threat model JSON object only. "
        "Use the provided ERC Threat Metamodel schema, contract context, "
        "retrieved knowledge, and deterministic baseline. "
        "Do not invent source paths or unsupported SWC mappings. "
        "Use SWC: \"N/A\" when no precise SWC mapping exists. "
        "Every threat must target assets, exploit vulnerabilities, be mitigated by "
        "countermeasures, violate security properties, and be validated by test objectives. "
        "Return only valid JSON, with no markdown."
    )
    user = (
        "Create an improved ETM threat model for this contract. "
        "Prefer contract-specific wording, preserve traceable knowledgeSources when useful, "
        "and keep IDs internally consistent.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_chat_completion(client: Any, model_name: str, messages: list[dict[str, str]]) -> tuple[str, str]:
    completion = client.chat.completions.create(
        model=model_name,
        messages=messages,
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    return completion.choices[0].message.content or "{}", "json_object"


def generate_llm_threat_model(
    contract_context: dict[str, Any],
    retrieved_knowledge: list[dict[str, Any]],
    deterministic_model: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set. Put it in .env or the process environment.")

    model_name = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL)

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("The openai package is required for --mode llm. Run: pip install -r requirements.txt") from exc

    client = OpenAI(api_key=api_key, base_url=GROQ_BASE_URL)
    payload = build_prompt_payload(contract_context, retrieved_knowledge, deterministic_model)
    messages = build_messages(payload)

    content, used_response_format = call_chat_completion(client, model_name, messages)
    model = parse_json_response(content)
    metadata = {
        "provider": "groq",
        "model": model_name,
        "base_url": GROQ_BASE_URL,
        "response_format": used_response_format,
        "knowledge_items_sent": len(payload["retrieved_knowledge"]),
    }
    return model, metadata
