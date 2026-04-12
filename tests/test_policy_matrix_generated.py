"""Generated policy enforcement matrix tests (source x taint x sink x profile)."""

from __future__ import annotations

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


def _runtime(tmp_path: Path, profile: str) -> MVARRuntime:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    runtime = MVARRuntime(profile=profile, witness_dir=witness_dir)
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime


def _input_class_for_taint(taint_level: str) -> str | None:
    if taint_level == "trusted":
        return InputClass.TRUSTED.value
    if taint_level == "untrusted":
        return InputClass.UNTRUSTED.value
    # Keep unknown unset to exercise provenance-based classification path.
    return None


MATRIX_CASES = generate_policy_matrix_cases()


@pytest.mark.parametrize("case", MATRIX_CASES, ids=[c.case_id for c in MATRIX_CASES])
def test_policy_matrix(case, tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, profile=case.profile)
    request = ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=case.sink_type,
        tool_name="matrix_tool",
        target=case.target,
        arguments={"target": case.target},
        input_class=_input_class_for_taint(case.taint_level),
        prompt_provenance={
            "source": case.source,
            "taint_level": case.taint_level,
            "source_chain": [case.source, "policy_matrix"],
            "taint_markers": [] if case.taint_level == "trusted" else ["matrix_untrusted"],
        },
        policy_profile=case.profile,
    )

    decision = runtime.evaluate(request)

    assert decision.decision == case.expected_decision
    assert decision.reason_code == case.expected_reason_code
    assert decision.policy_profile == case.expected_profile
    assert decision.annotations["effective_policy_profile"] == case.expected_profile
