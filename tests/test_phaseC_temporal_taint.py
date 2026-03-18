"""Phase C temporal taint tests: delayed activation tracking and enforcement."""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime


def _runtime(
    tmp_path: Path,
    *,
    temporal_taint_mode: str = "warn",
    delayed_taint_threshold_hours: float = 24.0,
) -> tuple[MVARRuntime, Path]:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    rt = MVARRuntime(
        profile="dev_balanced",
        witness_dir=witness_dir,
        temporal_taint_mode=temporal_taint_mode,
        delayed_taint_threshold_hours=delayed_taint_threshold_hours,
    )
    rt._mvar_available = False
    rt._mvar_governor = None
    rt.engine = "embedded-policy-v0.1"
    rt.policy_id = "mvar-embedded.v0.1"
    return rt, witness_dir


def _request(
    *,
    source_chain: list[str],
    taint_markers: list[str],
    first_seen_at: str,
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type="filesystem.read",
        tool_name="phaseC_tool",
        target="/workspace/report.md",
        arguments={"target": "/workspace/report.md"},
        input_class=InputClass.UNTRUSTED.value,
        prompt_provenance={
            "source": "agent_memory",
            "taint_level": "untrusted",
            "source_chain": source_chain,
            "taint_markers": taint_markers,
            "first_seen_at": first_seen_at,
        },
        policy_profile="dev_balanced",
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "event_intercept",
                "framework": "openclaw",
            }
        },
    )


def test_temporal_warn_mode_marks_delayed_trigger_without_block(tmp_path: Path) -> None:
    rt, _ = _runtime(tmp_path, temporal_taint_mode="warn")
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    decision = rt.evaluate(
        _request(
            source_chain=["agent_memory", "planner", "tool_call"],
            taint_markers=["persistent_memory"],
            first_seen_at=old,
        )
    )

    assert decision.decision == "allow"
    assert decision.reason_code == "ALLOWLIST_MATCH"
    temporal = decision.annotations["temporal_taint_status"]
    assert temporal["delayed_trigger_detected"] is True
    assert temporal["taint_age_hours"] >= 24.0

    witness = rt.last_witness
    assert witness is not None
    assert witness["temporal_taint_status"]["delayed_trigger_detected"] is True
    assert witness["delayed_trigger_detected"] is True
    assert witness["taint_age_hours"] >= 24.0


def test_temporal_enforce_mode_blocks_delayed_trigger(tmp_path: Path) -> None:
    rt, _ = _runtime(tmp_path, temporal_taint_mode="enforce")
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    decision = rt.evaluate(
        _request(
            source_chain=["agent_memory", "planner", "tool_call"],
            taint_markers=["memory_injection"],
            first_seen_at=old,
        )
    )

    assert decision.decision == "block"
    assert decision.reason_code == "DELAYED_TAINT_TRIGGER"
    assert decision.annotations["temporal_taint_guard"] is True


def test_temporal_does_not_trigger_without_memory_trace(tmp_path: Path) -> None:
    rt, _ = _runtime(tmp_path, temporal_taint_mode="warn")
    old = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    decision = rt.evaluate(
        _request(
            source_chain=["external_document", "planner", "tool_call"],
            taint_markers=["prompt_injection"],
            first_seen_at=old,
        )
    )

    temporal = decision.annotations["temporal_taint_status"]
    assert temporal["has_memory_trace"] is False
    assert temporal["delayed_trigger_detected"] is False
    assert decision.decision == "allow"


def test_replay_shows_temporal_chain_line(tmp_path: Path, capsys) -> None:
    rt, witness_dir = _runtime(tmp_path, temporal_taint_mode="warn")
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    rt.evaluate(
        _request(
            source_chain=["agent_memory", "planner", "tool_call"],
            taint_markers=["persistent_memory"],
            first_seen_at=old,
        )
    )

    rc = cli.main(["replay", "--session", str(witness_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Temporal: age=" in out
