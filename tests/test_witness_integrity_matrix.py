"""Witness integrity checks across the generated policy matrix."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime
from policy_matrix_data import generate_policy_matrix_cases


def _runtime(tmp_path: Path, profile: str) -> tuple[MVARRuntime, Path]:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    runtime = MVARRuntime(profile=profile, witness_dir=witness_dir)
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime, witness_dir


def _input_class_for_taint(taint_level: str) -> str | None:
    if taint_level == "trusted":
        return InputClass.TRUSTED.value
    if taint_level == "untrusted":
        return InputClass.UNTRUSTED.value
    return None


def _evaluate_case(case, tmp_path: Path) -> tuple[MVARRuntime, Path, ActionRequest]:
    runtime, witness_dir = _runtime(tmp_path, profile=case.profile)
    request = ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=case.sink_type,
        tool_name="witness_matrix_tool",
        target=case.target,
        arguments={"target": case.target},
        input_class=_input_class_for_taint(case.taint_level),
        prompt_provenance={
            "source": case.source,
            "taint_level": case.taint_level,
            "source_chain": [case.source, "witness_matrix"],
            "taint_markers": [] if case.taint_level == "trusted" else ["witness_matrix_untrusted"],
        },
        policy_profile=case.profile,
    )
    runtime.evaluate(request)
    return runtime, witness_dir, request


MATRIX_CASES = generate_policy_matrix_cases()


@pytest.mark.parametrize("case", MATRIX_CASES, ids=[c.case_id for c in MATRIX_CASES])
def test_witness_generated_for_matrix_case(case, tmp_path: Path) -> None:
    runtime, witness_dir, _request = _evaluate_case(case, tmp_path)
    witness = runtime.last_witness
    assert isinstance(witness, dict)
    assert witness.get("witness_id")
    assert any(witness_dir.glob("*.json"))


@pytest.mark.parametrize("case", MATRIX_CASES, ids=[c.case_id for c in MATRIX_CASES])
def test_witness_signature_present_for_matrix_case(case, tmp_path: Path) -> None:
    runtime, _witness_dir, _request = _evaluate_case(case, tmp_path)
    witness = runtime.last_witness
    assert isinstance(witness, dict)
    signature = str(witness.get("witness_signature", ""))
    assert signature.startswith("ed25519:") or signature.startswith("ed25519_stub:")


@pytest.mark.parametrize("case", MATRIX_CASES, ids=[c.case_id for c in MATRIX_CASES])
def test_witness_causal_trace_for_matrix_case(case, tmp_path: Path) -> None:
    runtime, witness_dir, request = _evaluate_case(case, tmp_path)
    witness = runtime.last_witness
    assert isinstance(witness, dict)
    assert witness.get("reason_code")
    assert witness.get("sink_type") == case.sink_type
    assert witness.get("target") == case.target

    provenance = witness.get("provenance", {})
    assert isinstance(provenance, dict)
    assert provenance.get("source") == case.source
    assert provenance.get("source_chain")
    assert provenance.get("taint_level") in {"trusted", "untrusted"}

    # File contents should match the in-memory witness id.
    files = list(witness_dir.glob("*.json"))
    assert files
    loaded = json.loads(files[-1].read_text(encoding="utf-8"))
    assert loaded.get("witness_id") == witness.get("witness_id")
    assert loaded.get("request_id") == request.request_id
