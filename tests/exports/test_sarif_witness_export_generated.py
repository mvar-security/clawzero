"""Generated SARIF + witness export matrix suite (Phase 8).

Adds 300 scenarios:
  - 150 SARIF report construction/validation cases
  - 150 witness verification/export integrity cases
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from itertools import islice, product
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero import __version__
from clawzero.sarif import build_sarif_report, validate_sarif_report
from clawzero.witnesses.verify import verify_witness_object

try:
    from jsonschema import Draft7Validator
except Exception:  # pragma: no cover - guarded by test skip
    Draft7Validator = None  # type: ignore[assignment]

DECISIONS: tuple[str, ...] = ("allow", "annotate", "block")
SINKS: tuple[str, ...] = (
    "tool.custom",
    "http.request",
    "filesystem.read",
    "filesystem.write",
    "credentials.access",
    "shell.exec",
)
REASON_CODES: tuple[str, ...] = (
    "POLICY_ALLOW",
    "STEP_UP_REQUIRED",
    "UNTRUSTED_TO_CRITICAL_SINK",
    "DOMAIN_BLOCKED",
    "PATH_BLOCKED",
)
ENGINES: tuple[str, ...] = ("embedded-policy-v0.1", "mvar-security")
SOURCES: tuple[str, ...] = ("user_request", "external_document", "api_response")
TAINTS: tuple[str, ...] = ("trusted", "untrusted")
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"


@dataclass(frozen=True)
class SarifCase:
    index: int
    decision: str
    sink_type: str
    reason_code: str
    engine: str
    source: str

    @property
    def case_id(self) -> str:
        return (
            f"sarif_{self.index:03d}__{self.decision}__"
            f"{self.sink_type.replace('.', '_')}__{self.reason_code.lower()}"
        )


@dataclass(frozen=True)
class WitnessCase:
    index: int
    decision: str
    sink_type: str
    reason_code: str
    source: str
    taint_level: str

    @property
    def case_id(self) -> str:
        return (
            f"witness_{self.index:03d}__{self.decision}__"
            f"{self.sink_type.replace('.', '_')}__{self.taint_level}"
        )


def _sarif_cases() -> list[SarifCase]:
    combos = product(DECISIONS, SINKS, REASON_CODES, ENGINES, SOURCES)
    return [
        SarifCase(
            index=i,
            decision=decision,
            sink_type=sink_type,
            reason_code=reason_code,
            engine=engine,
            source=source,
        )
        for i, (decision, sink_type, reason_code, engine, source) in enumerate(islice(combos, 150), start=1)
    ]


def _witness_cases() -> list[WitnessCase]:
    combos = product(DECISIONS, SINKS, REASON_CODES, SOURCES, TAINTS)
    return [
        WitnessCase(
            index=i,
            decision=decision,
            sink_type=sink_type,
            reason_code=reason_code,
            source=source,
            taint_level=taint_level,
        )
        for i, (decision, sink_type, reason_code, source, taint_level) in enumerate(
            islice(combos, 150), start=1
        )
    ]


def _sarif_level(decision: str) -> str:
    if decision == "block":
        return "error"
    if decision == "annotate":
        return "warning"
    return "note"


def _with_content_hash(payload: dict[str, Any]) -> dict[str, Any]:
    witness = dict(payload)
    canonical = json.dumps(witness, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    witness["content_hash"] = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    return witness


@lru_cache(maxsize=1)
def _official_sarif_validator() -> Any:
    if Draft7Validator is None:
        pytest.skip("jsonschema is unavailable")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema)


@pytest.mark.parametrize("case", [pytest.param(case, id=case.case_id) for case in _sarif_cases()])
def test_sarif_export_generated(case: SarifCase) -> None:
    witness = {
        "witness_id": f"w-{case.index:03d}",
        "decision": case.decision,
        "reason_code": case.reason_code,
        "sink_type": case.sink_type,
        "target": f"target://{case.source}/{case.index:03d}",
        "policy_id": "mvar-embedded.v0.1",
        "engine": case.engine,
        "chain_index": 1,
        "_source_file": f"witness_{case.index:03d}.json",
    }

    report = build_sarif_report([witness], tool_version=__version__)
    assert validate_sarif_report(report) == []
    errors = sorted(_official_sarif_validator().iter_errors(report), key=lambda item: item.path)
    assert errors == []

    result = report["runs"][0]["results"][0]
    assert result["properties"]["decision"] == case.decision
    assert result["properties"]["reason_code"] == case.reason_code
    assert result["properties"]["engine"] == case.engine
    assert result["level"] == _sarif_level(case.decision)


@pytest.mark.parametrize("case", [pytest.param(case, id=case.case_id) for case in _witness_cases()])
def test_witness_export_generated(case: WitnessCase) -> None:
    base = {
        "timestamp": f"2026-04-12T20:{case.index % 60:02d}:00+00:00",
        "agent_runtime": "clawzero",
        "sink_type": case.sink_type,
        "target": f"target://{case.source}/{case.index:03d}",
        "decision": case.decision,
        "reason_code": case.reason_code,
        "policy_id": "mvar-embedded.v0.1",
        "engine": "embedded-policy-v0.1",
        "provenance": {
            "source": case.source,
            "taint_level": case.taint_level,
            "source_chain": [case.source, "tool_call"],
            "taint_markers": [] if case.taint_level == "trusted" else ["external_content"],
        },
        "adapter": {
            "name": "generated",
            "framework": "matrix",
            "mode": "test",
        },
        "witness_signature": "ed25519_stub:0123456789abcdef",
        "schema_version": "1.1",
        "chain_index": 1,
        "previous_hash": "genesis",
    }
    witness = _with_content_hash(base)

    valid = verify_witness_object(witness, require_chain=True)
    assert valid.valid is True
    assert valid.reasons == []

    tampered = dict(witness)
    tampered["reason_code"] = "TAMPERED_REASON"
    invalid = verify_witness_object(tampered, require_chain=True)
    assert invalid.valid is False
    assert any("content_hash mismatch" in reason for reason in invalid.reasons)
