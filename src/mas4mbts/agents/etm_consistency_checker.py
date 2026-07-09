"""Consistency checks for generated ETM threat models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.mas4mbts.agents.erc_threat_model_agent import normalize_erc_id, validate_etm_instance


RELATION_REQUIREMENTS = {
    "targets": "assets",
    "exploits": "vulnerabilities",
    "mitigatedBy": "countermeasures",
    "violates": "securityProperties",
    "validatedBy": "testObjectives",
}


ID_SECTIONS = [
    "actors",
    "trustLevels",
    "assets",
    "entryPoints",
    "vulnerabilities",
    "threats",
    "countermeasures",
    "securityProperties",
    "testObjectives",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def collect_ids(model: dict[str, Any]) -> dict[str, set[str]]:
    ids: dict[str, set[str]] = {}
    for section in ID_SECTIONS:
        ids[section] = {item.get("id", "") for item in model.get(section, []) if item.get("id")}
    ids["smartContract"] = {model.get("smartContract", {}).get("id", "")}
    ids["ercStandard"] = {model.get("ercStandard", {}).get("id", "")}
    ids["all"] = set().union(*ids.values())
    return ids


def relation_targets(model: dict[str, Any], relation_type: str, threat_id: str) -> set[str]:
    return {
        relation.get("to", "")
        for relation in model.get("relations", [])
        if relation.get("type") == relation_type and relation.get("from") == threat_id
    }


def check_schema(model: dict[str, Any]) -> tuple[bool, list[str]]:
    try:
        validate_etm_instance(model)
    except Exception as exc:
        return False, [str(exc)]
    return True, []


def check_standard_match(model: dict[str, Any], context: dict[str, Any] | None) -> tuple[bool, str | None]:
    if not context:
        return True, None
    expected = normalize_erc_id(context.get("ercStandard"))
    actual = normalize_erc_id(model.get("ercStandard", {}).get("name"))
    if expected == actual:
        return True, None
    return False, f"Standard mismatch: context={expected}, model={actual}"


def check_duplicate_ids(ids: dict[str, set[str]], model: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    seen: dict[str, str] = {}
    for section in ID_SECTIONS:
        for item in model.get(section, []):
            item_id = item.get("id")
            if not item_id:
                continue
            if item_id in seen:
                issues.append(f"Duplicate id {item_id!r} in {seen[item_id]} and {section}.")
            seen[item_id] = section
    return issues


def check_relations(model: dict[str, Any], ids: dict[str, set[str]]) -> list[str]:
    issues: list[str] = []
    for index, relation in enumerate(model.get("relations", []), start=1):
        relation_type = relation.get("type", "")
        source = relation.get("from", "")
        target = relation.get("to", "")
        if source not in ids["all"]:
            issues.append(f"Relation {index} has unknown source id {source!r}.")
        if target not in ids["all"]:
            issues.append(f"Relation {index} has unknown target id {target!r}.")
        expected_section = RELATION_REQUIREMENTS.get(relation_type)
        if expected_section and target not in ids[expected_section]:
            issues.append(
                f"Relation {index} type {relation_type!r} points to {target!r}, "
                f"not a member of {expected_section}."
            )
    return issues


def check_threat_coverage(model: dict[str, Any], ids: dict[str, set[str]]) -> tuple[list[str], dict[str, list[str]]]:
    issues: list[str] = []
    missing: dict[str, list[str]] = {relation_type: [] for relation_type in RELATION_REQUIREMENTS}
    for threat in model.get("threats", []):
        threat_id = threat.get("id", "")
        if not threat_id:
            continue
        for relation_type, target_section in RELATION_REQUIREMENTS.items():
            targets = relation_targets(model, relation_type, threat_id)
            valid_targets = targets & ids[target_section]
            if not valid_targets:
                missing[relation_type].append(threat_id)
                issues.append(f"Threat {threat_id} has no valid {relation_type} relation.")
    return issues, missing


def check_knowledge_sources(model: dict[str, Any]) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    warnings: list[str] = []
    if not model.get("knowledgeSources"):
        warnings.append("Model has no top-level knowledgeSources.")

    for section in ["vulnerabilities", "threats", "countermeasures", "testObjectives"]:
        for item in model.get(section, []):
            if not item.get("knowledgeSources"):
                warnings.append(f"{section}:{item.get('id', '<missing-id>')} has no knowledgeSources.")
    return issues, warnings


def coverage_counts(model: dict[str, Any]) -> dict[str, int]:
    return {
        "actors": len(model.get("actors", [])),
        "trustLevels": len(model.get("trustLevels", [])),
        "assets": len(model.get("assets", [])),
        "entryPoints": len(model.get("entryPoints", [])),
        "vulnerabilities": len(model.get("vulnerabilities", [])),
        "threats": len(model.get("threats", [])),
        "countermeasures": len(model.get("countermeasures", [])),
        "securityProperties": len(model.get("securityProperties", [])),
        "testObjectives": len(model.get("testObjectives", [])),
        "relations": len(model.get("relations", [])),
        "knowledgeSources": len(model.get("knowledgeSources", [])),
    }


def swc_summary(model: dict[str, Any]) -> dict[str, Any]:
    values = [item.get("SWC", "N/A") for item in model.get("vulnerabilities", [])]
    na_count = sum(1 for value in values if not value or value == "N/A")
    mapped = sorted({value for value in values if value and value != "N/A"})
    return {"na_count": na_count, "mapped": mapped}


def build_report(model: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    schema_valid, schema_errors = check_schema(model)
    ids = collect_ids(model)
    standard_match, standard_issue = check_standard_match(model, context)

    issues: list[str] = []
    warnings: list[str] = []
    issues.extend(schema_errors)
    if standard_issue:
        issues.append(standard_issue)
    issues.extend(check_duplicate_ids(ids, model))
    issues.extend(check_relations(model, ids))
    threat_issues, missing_relations = check_threat_coverage(model, ids)
    issues.extend(threat_issues)
    knowledge_issues, knowledge_warnings = check_knowledge_sources(model)
    issues.extend(knowledge_issues)
    warnings.extend(knowledge_warnings)

    swc = swc_summary(model)
    if swc["na_count"]:
        warnings.append(f"{swc['na_count']} vulnerabilities have SWC: N/A.")

    return {
        "schema_valid": schema_valid,
        "consistent": schema_valid and standard_match and not issues,
        "standard_match": standard_match,
        "standard": {
            "context": context.get("ercStandard") if context else None,
            "model": model.get("ercStandard", {}).get("name"),
        },
        "coverage": coverage_counts(model),
        "missing_relations": missing_relations,
        "swc": swc,
        "issues": issues,
        "warnings": warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ETM schema and consistency of a threat model.")
    parser.add_argument("--model", required=True, type=Path, help="Path to an ETM threat model JSON file.")
    parser.add_argument("--context", type=Path, help="Optional contract context JSON for standard matching.")
    parser.add_argument("--output", type=Path, help="Optional path where the validation report is written.")
    args = parser.parse_args()

    model = load_json(args.model)
    context = load_json(args.context) if args.context else None
    report = build_report(model, context=context)

    if args.output:
        write_json(args.output, report)
        print(f"Validation report written: {args.output}")
    else:
        print(json.dumps(report, indent=2))

    if not report["consistent"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
