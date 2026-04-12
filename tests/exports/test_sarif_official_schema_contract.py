"""Official SARIF 2.1.0 schema contract tests.

Uses the canonical SARIF schema (vendored in tests/schemas) to ensure
ClawZero SARIF output is valid beyond the internal lightweight validator.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero.sarif import build_sarif_report

try:
    from jsonschema import Draft7Validator
except Exception:  # pragma: no cover - guarded by test skip
    Draft7Validator = None  # type: ignore[assignment]


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"


def _validator() -> Draft7Validator:
    if Draft7Validator is None:
        pytest.skip("jsonschema is unavailable")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema)


def _single_witness(decision: str, reason_code: str, sink_type: str, idx: int) -> dict[str, object]:
    return {
        "witness_id": f"w-{idx:03d}",
        "decision": decision,
        "reason_code": reason_code,
        "sink_type": sink_type,
        "target": f"target://scenario/{idx:03d}",
        "policy_id": "mvar-embedded.v0.1",
        "engine": "embedded-policy-v0.1",
        "chain_index": 1,
        "_source_file": f"witness_{idx:03d}.json",
    }


@pytest.mark.parametrize(
    "decision,reason,sink",
    [
        ("allow", "POLICY_ALLOW", "tool.custom"),
        ("annotate", "STEP_UP_REQUIRED", "http.request"),
        ("block", "UNTRUSTED_TO_CRITICAL_SINK", "shell.exec"),
        ("block", "PATH_BLOCKED", "filesystem.read"),
        ("block", "DOMAIN_BLOCKED", "http.request"),
        ("block", "CREDENTIAL_ACCESS_BLOCKED", "credentials.access"),
    ],
)
def test_sarif_report_validates_against_official_schema(
    decision: str,
    reason: str,
    sink: str,
) -> None:
    validator = _validator()
    report = build_sarif_report([_single_witness(decision, reason, sink, 1)], tool_version="0.3.0")
    errors = sorted(validator.iter_errors(report), key=lambda item: item.path)
    assert errors == []


def test_official_schema_rejects_invalid_sarif_structure() -> None:
    validator = _validator()
    bad_report = {
        "version": "2.1.1",  # invalid SARIF version
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {"driver": {"name": "ClawZero", "version": "0.3.0", "rules": []}},
                "results": [
                    {
                        # invalid on purpose: ruleId omitted
                        "level": "error",
                        "message": {"text": "broken"},
                    }
                ],
            }
        ],
    }
    errors = sorted(validator.iter_errors(bad_report), key=lambda item: item.path)
    assert errors, "official SARIF schema should reject malformed report payload"
