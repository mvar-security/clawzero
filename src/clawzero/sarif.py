"""SARIF export utilities for ClawZero witness artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


@dataclass
class SarifExportResult:
    output: Path
    witness_count: int
    result_count: int


def export_sarif(input_dir: Path, output_file: Path, tool_version: str = "0.1.1") -> SarifExportResult:
    witnesses = load_witnesses(input_dir)
    sarif = build_sarif_report(witnesses=witnesses, tool_version=tool_version)
    validation_errors = validate_sarif_report(sarif)
    if validation_errors:
        joined = "; ".join(validation_errors)
        raise ValueError(f"SARIF validation failed: {joined}")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return SarifExportResult(
        output=output_file,
        witness_count=len(witnesses),
        result_count=len(sarif["runs"][0]["results"]),
    )


def load_witnesses(input_dir: Path) -> list[dict[str, Any]]:
    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Witness directory not found: {input_dir}")

    witnesses: list[dict[str, Any]] = []
    for file in sorted(input_dir.glob("*.json")):
        try:
            witness = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        witness["_source_file"] = file.name
        witnesses.append(witness)

    if not witnesses:
        raise ValueError(f"No witness JSON files found in {input_dir}")

    return sorted(
        witnesses,
        key=lambda item: (
            int(item.get("chain_index", 0)),
            str(item.get("_source_file", "")),
        ),
    )


def build_sarif_report(witnesses: list[dict[str, Any]], tool_version: str) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for witness in witnesses:
        reason_code = str(witness.get("reason_code", "UNKNOWN_REASON"))
        decision = str(witness.get("decision", "annotate")).lower()
        sink_type = str(witness.get("sink_type", "tool.custom"))
        target = str(witness.get("target", "agent_action"))
        policy_id = str(witness.get("policy_id", "unknown_policy"))
        engine = str(witness.get("engine", "unknown_engine"))
        witness_id = str(witness.get("witness_id", "unknown_witness"))

        rule_id = f"clawzero/{reason_code.lower()}"
        level = _level_for_decision(decision)
        message = (
            f"ClawZero decision={decision} reason={reason_code} "
            f"sink={sink_type} target={target}"
        )

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": reason_code,
                "shortDescription": {"text": reason_code},
                "fullDescription": {"text": f"ClawZero policy outcome for {reason_code}"},
                "defaultConfiguration": {"level": level},
                "help": {"text": "Review witness artifact for deterministic execution decision."},
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "kind": "sink",
                                "name": sink_type,
                            }
                        ],
                    }
                ],
                "properties": {
                    "decision": decision,
                    "reason_code": reason_code,
                    "policy_id": policy_id,
                    "engine": engine,
                    "witness_id": witness_id,
                    "chain_index": witness.get("chain_index"),
                    "source_file": witness.get("_source_file"),
                },
            }
        )

    report = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA_URI,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ClawZero",
                        "version": tool_version,
                        "informationUri": "https://github.com/mvar-security/clawzero",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return report


def validate_sarif_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if report.get("version") != "2.1.0":
        errors.append("version must be 2.1.0")
    if not str(report.get("$schema", "")).endswith("sarif-schema-2.1.0.json"):
        errors.append("schema must reference sarif 2.1.0")

    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must contain at least one run")
        return errors

    run = runs[0]
    tool = run.get("tool", {})
    driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
    if driver.get("name") != "ClawZero":
        errors.append("tool.driver.name must be ClawZero")

    results = run.get("results")
    if not isinstance(results, list):
        errors.append("run results must be a list")
        return errors

    for idx, result in enumerate(results, start=1):
        if not result.get("ruleId"):
            errors.append(f"result {idx} missing ruleId")
        message = result.get("message", {})
        if not isinstance(message, dict) or not message.get("text"):
            errors.append(f"result {idx} missing message.text")
        level = str(result.get("level", ""))
        if level not in {"error", "warning", "note"}:
            errors.append(f"result {idx} invalid level '{level}'")
        locations = result.get("locations", [])
        if not isinstance(locations, list) or not locations:
            errors.append(f"result {idx} missing locations")

    return errors


def _level_for_decision(decision: str) -> str:
    if decision == "block":
        return "error"
    if decision == "annotate":
        return "warning"
    return "note"

