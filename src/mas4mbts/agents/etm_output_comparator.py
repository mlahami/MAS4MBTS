"""Compare deterministic and LLM-assisted ETM outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def names(model: dict[str, Any], section: str, field: str) -> set[str]:
    return {item.get(field, "") for item in model.get(section, []) if item.get(field)}


def compare_sets(left: set[str], right: set[str]) -> dict[str, list[str]]:
    return {
        "common": sorted(left & right),
        "only_mode_a": sorted(left - right),
        "only_mode_b": sorted(right - left),
    }


def build_comparison(
    mode_a_model: dict[str, Any],
    mode_b_model: dict[str, Any],
    mode_a_report: dict[str, Any] | None = None,
    mode_b_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "mode_a": {
            "name": "deterministic",
            "standard": mode_a_model.get("ercStandard", {}).get("name"),
            "coverage": (mode_a_report or {}).get("coverage", {}),
            "consistent": (mode_a_report or {}).get("consistent"),
            "issues": (mode_a_report or {}).get("issues", []),
            "warnings": (mode_a_report or {}).get("warnings", []),
        },
        "mode_b": {
            "name": "llm",
            "standard": mode_b_model.get("ercStandard", {}).get("name"),
            "coverage": (mode_b_report or {}).get("coverage", {}),
            "consistent": (mode_b_report or {}).get("consistent"),
            "issues": (mode_b_report or {}).get("issues", []),
            "warnings": (mode_b_report or {}).get("warnings", []),
        },
        "differences": {
            "threats": compare_sets(
                names(mode_a_model, "threats", "threatName"),
                names(mode_b_model, "threats", "threatName"),
            ),
            "vulnerabilities": compare_sets(
                names(mode_a_model, "vulnerabilities", "vulnerabilityName"),
                names(mode_b_model, "vulnerabilities", "vulnerabilityName"),
            ),
            "countermeasures": compare_sets(
                names(mode_a_model, "countermeasures", "countermeasureName"),
                names(mode_b_model, "countermeasures", "countermeasureName"),
            ),
            "testObjectives": compare_sets(
                names(mode_a_model, "testObjectives", "objectiveName"),
                names(mode_b_model, "testObjectives", "objectiveName"),
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Mode A deterministic and Mode B LLM ETM outputs.")
    parser.add_argument("--mode-a-model", required=True, type=Path)
    parser.add_argument("--mode-b-model", required=True, type=Path)
    parser.add_argument("--mode-a-report", type=Path)
    parser.add_argument("--mode-b-report", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    comparison = build_comparison(
        load_json(args.mode_a_model),
        load_json(args.mode_b_model),
        load_json(args.mode_a_report) if args.mode_a_report else None,
        load_json(args.mode_b_report) if args.mode_b_report else None,
    )
    write_json(args.output, comparison)
    print(f"Comparison report written: {args.output}")


if __name__ == "__main__":
    main()
