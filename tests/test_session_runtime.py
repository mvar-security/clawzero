"""AgentSession behavior and engine integration tests."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

for module_name in list(sys.modules):
    if module_name == "clawzero" or module_name.startswith("clawzero."):
        sys.modules.pop(module_name)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.contracts import ActionDecision, ActionRequest, InputClass  # noqa: E402
from clawzero.runtime import AgentSession, MVARRuntime  # noqa: E402


def _decision(
    *,
    sink_type: str = "tool.custom",
    decision: str = "allow",
    taint_level: str = "trusted",
    source: str = "user_request",
) -> ActionDecision:
    return ActionDecision(
        request_id=str(uuid.uuid4()),
        decision=decision,
        reason_code="POLICY_ALLOW" if decision == "allow" else "UNTRUSTED_TO_CRITICAL_SINK",
        human_reason=decision,
        sink_type=sink_type,
        target="target",
        policy_profile="dev_balanced",
        annotations={
            "provenance": {
                "source": source,
                "taint_level": taint_level,
            },
            "input_class": taint_level,
        },
        trust_level=taint_level,
    )


def _request(*, sink_type: str = "shell.exec", taint_level: str = "untrusted") -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="tool",
        target="bash",
        arguments={"command": "id"},
        input_class=InputClass.UNTRUSTED.value if taint_level == "untrusted" else InputClass.TRUSTED.value,
        prompt_provenance={
            "source": "external_document" if taint_level == "untrusted" else "user_request",
            "taint_level": taint_level,
            "source_chain": ["source", "tool_call"],
            "taint_markers": ["prompt_injection"] if taint_level == "untrusted" else [],
        },
        policy_profile="prod_locked",
    )


def _runtime(tmp_path: Path) -> MVARRuntime:
    runtime = MVARRuntime(profile="prod_locked", witness_dir=tmp_path / "witnesses")
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime


def test_session_generates_log_path(tmp_path: Path) -> None:
    session = AgentSession(profile="dev_balanced", persistence_root=tmp_path)
    assert session.log_path.parent == tmp_path
    assert session.log_path.name.endswith(".jsonl")


def test_session_evaluate_appends_jsonl_record(tmp_path: Path) -> None:
    session = AgentSession(session_id="s1", profile="dev_balanced", persistence_root=tmp_path)
    decision = session.evaluate(_decision(taint_level="trusted"))
    assert decision.annotations["session"]["session_id"] == "s1"
    lines = session.log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert '"request_id"' in lines[0]


def test_untrusted_decision_increases_escalation_score(tmp_path: Path) -> None:
    session = AgentSession(session_id="s2", profile="dev_balanced", persistence_root=tmp_path)
    session.evaluate(_decision(sink_type="http.request", taint_level="untrusted"))
    assert session.escalation_score >= 1.5


def test_blocked_decision_adds_penalty(tmp_path: Path) -> None:
    session = AgentSession(session_id="s3", profile="dev_balanced", persistence_root=tmp_path)
    session.evaluate(
        _decision(
            sink_type="shell.exec",
            decision="block",
            taint_level="untrusted",
            source="external_document",
        )
    )
    assert session.escalation_score > 3.0


def test_profile_auto_escalates_balanced_to_strict(tmp_path: Path) -> None:
    session = AgentSession(session_id="s4", profile="dev_balanced", persistence_root=tmp_path)
    for _ in range(2):
        session.evaluate(_decision(sink_type="shell.exec", taint_level="untrusted", source="x"))
    assert session.profile == "dev_strict"


def test_profile_auto_escalates_strict_to_prod_locked(tmp_path: Path) -> None:
    session = AgentSession(session_id="s5", profile="dev_strict", persistence_root=tmp_path)
    for _ in range(3):
        session.evaluate(_decision(sink_type="shell.exec", taint_level="untrusted", source="x"))
    assert session.profile == "prod_locked"


def test_prod_locked_does_not_escalate_further(tmp_path: Path) -> None:
    session = AgentSession(session_id="s6", profile="prod_locked", persistence_root=tmp_path)
    for _ in range(5):
        session.evaluate(_decision(sink_type="shell.exec", taint_level="untrusted", source="x"))
    assert session.profile == "prod_locked"


def test_cross_session_isolation(tmp_path: Path) -> None:
    session_a = AgentSession(session_id="A", profile="dev_balanced", persistence_root=tmp_path)
    session_b = AgentSession(session_id="B", profile="dev_balanced", persistence_root=tmp_path)
    session_a.evaluate(_decision(sink_type="shell.exec", taint_level="untrusted", source="x"))
    assert session_a.escalation_score > 0.0
    assert session_b.escalation_score == 0.0
    assert len(session_b.decisions) == 0


def test_chain_detection_uses_source_independent_taint_continuity(tmp_path: Path) -> None:
    session = AgentSession(session_id="s7", profile="dev_balanced", persistence_root=tmp_path)
    session.evaluate(_decision(sink_type="http.request", taint_level="untrusted", source="a"))
    session.evaluate(_decision(sink_type="filesystem.read", taint_level="untrusted", source="b"))
    enriched = session.evaluate(_decision(sink_type="shell.exec", taint_level="untrusted", source="c"))
    chain_patterns = [
        item["pattern"] for item in enriched.annotations["session"]["chain_detections"]
    ]
    assert "taint_continuity" in chain_patterns


def test_attach_witness_increments_chain_length(tmp_path: Path) -> None:
    session = AgentSession(session_id="s8", profile="dev_balanced", persistence_root=tmp_path)
    session.attach_witness({"witness_id": "w1"})
    assert session.get_session_report()["witness_chain_length"] == 1


def test_session_report_contains_expected_fields(tmp_path: Path) -> None:
    session = AgentSession(session_id="s9", profile="dev_balanced", persistence_root=tmp_path)
    session.evaluate(_decision(sink_type="tool.custom", taint_level="trusted"))
    report = session.get_session_report()
    assert report["session_id"] == "s9"
    assert report["total_calls"] == 1
    assert "chain_detector" in report
    assert report["log_path"].endswith("s9.jsonl")


def test_close_marks_session_closed(tmp_path: Path) -> None:
    session = AgentSession(session_id="s10", profile="dev_balanced", persistence_root=tmp_path)
    session.close()
    with pytest.raises(RuntimeError):
        session.evaluate(_decision())


def test_engine_evaluate_with_session_enriches_decision(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    session = AgentSession(session_id="eng1", profile="dev_balanced", persistence_root=tmp_path / "sessions")
    decision = runtime.evaluate(_request(sink_type="shell.exec", taint_level="untrusted"), session=session)
    assert decision.annotations["session"]["session_id"] == "eng1"
    assert session.get_session_report()["witness_chain_length"] == 1


def test_engine_evaluate_without_session_is_unchanged(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    decision = runtime.evaluate(_request(sink_type="shell.exec", taint_level="untrusted"))
    assert "session" not in decision.annotations
