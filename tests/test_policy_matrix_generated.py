"""Generated policy enforcement matrix tests (source x taint x sink x profile)."""

from __future__ import annotations

from collections import defaultdict
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime
from policy_matrix_data import TARGET_BY_SINK, generate_policy_matrix_cases


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


def _expected_witness_taint_level(taint_level: str) -> str:
    # Engine contract: unknown and untrusted inputs normalize to untrusted.
    if taint_level in {"unknown", "untrusted"}:
        return "untrusted"
    return taint_level


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
    assert decision.sink_type == case.sink_type
    assert decision.target == case.target
    assert decision.policy_profile == case.expected_profile
    assert decision.annotations["effective_policy_profile"] == case.expected_profile

    witness = runtime.last_witness
    assert isinstance(witness, dict)
    assert witness.get("request_id") == decision.request_id
    assert witness.get("decision") == case.expected_decision
    assert witness.get("reason_code") == case.expected_reason_code
    assert witness.get("sink_type") == case.sink_type
    assert witness.get("target") == case.target
    assert witness.get("policy_id") == decision.policy_id

    provenance = witness.get("provenance")
    assert isinstance(provenance, dict)
    assert provenance.get("source") == case.source
    assert provenance.get("taint_level") == _expected_witness_taint_level(case.taint_level)
    assert provenance.get("source_chain") == [case.source, "policy_matrix"]
    expected_markers = [] if case.taint_level == "trusted" else ["matrix_untrusted"]
    assert provenance.get("taint_markers") == expected_markers


def test_policy_matrix_contract_source_dimension_is_explicitly_invariant() -> None:
    """Source values are coverage labels; enforcement is driven by taint/sink/profile."""
    by_contract_key: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
    for case in MATRIX_CASES:
        by_contract_key[(case.taint_level, case.sink_type, case.profile)].add(
            (case.expected_decision, case.expected_reason_code, case.expected_profile)
        )

    for key, outcomes in by_contract_key.items():
        assert len(outcomes) == 1, f"Source-invariance violated for {key}: {outcomes}"


def test_policy_matrix_contract_fixed_targets_define_scope() -> None:
    """Matrix target choices are explicit and define current coverage boundaries."""
    assert TARGET_BY_SINK["filesystem.read"] == "/etc/passwd"
    filesystem_read_cases = [case for case in MATRIX_CASES if case.sink_type == "filesystem.read"]
    assert filesystem_read_cases
    for case in filesystem_read_cases:
        assert case.target == "/etc/passwd"
        assert case.expected_decision == "block"
        assert case.expected_reason_code == "PATH_BLOCKED"


def test_policy_matrix_gap_filesystem_read_allow_paths_not_covered() -> None:
    pytest.skip(
        "Gap (explicit): this matrix intentionally pins filesystem.read to /etc/passwd, "
        "so allowlist read paths (for example /workspace/project/*) are out of scope here."
    )
