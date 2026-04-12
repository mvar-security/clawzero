"""Generated cross-session isolation suite (Phase 7).

This suite adds 50 scenarios to prove session state isolation:
  - escalation score does not leak across sessions
  - chain detector event history stays session-local
  - append-only JSONL logs remain isolated per session id
"""

from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass
from itertools import islice, product
from pathlib import Path

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero.contracts import ActionDecision
from clawzero.runtime import AgentSession

PROFILES: tuple[str, ...] = ("dev_balanced", "dev_strict", "prod_locked")
SINKS: tuple[str, ...] = (
    "tool.custom",
    "http.request",
    "filesystem.read",
    "filesystem.write",
    "credentials.access",
    "shell.exec",
)
TAINTS: tuple[str, ...] = ("trusted", "untrusted")


@dataclass(frozen=True)
class IsolationCase:
    index: int
    profile_a: str
    profile_b: str
    sink_type: str
    taint_level: str
    decision_a: str
    close_a_before_b: bool

    @property
    def case_id(self) -> str:
        close_token = "closeA" if self.close_a_before_b else "keepA"
        return (
            f"s{self.index:02d}__{self.profile_a}__{self.profile_b}__"
            f"{self.sink_type.replace('.', '_')}__{self.taint_level}__"
            f"{self.decision_a}__{close_token}"
        )


def generate_isolation_cases() -> list[IsolationCase]:
    combos = product(PROFILES, PROFILES, SINKS, TAINTS)
    cases: list[IsolationCase] = []
    for index, (profile_a, profile_b, sink_type, taint_level) in enumerate(islice(combos, 50), start=1):
        decision_a = "block" if taint_level == "untrusted" and sink_type in {"shell.exec", "credentials.access"} else "allow"
        cases.append(
            IsolationCase(
                index=index,
                profile_a=profile_a,
                profile_b=profile_b,
                sink_type=sink_type,
                taint_level=taint_level,
                decision_a=decision_a,
                close_a_before_b=(index % 2 == 0),
            )
        )
    return cases


def _decision(
    *,
    request_id: str,
    sink_type: str,
    decision: str,
    taint_level: str,
    source: str,
    profile: str,
) -> ActionDecision:
    reason = "POLICY_ALLOW" if decision == "allow" else "UNTRUSTED_TO_CRITICAL_SINK"
    return ActionDecision(
        request_id=request_id,
        decision=decision,
        reason_code=reason,
        human_reason=decision,
        sink_type=sink_type,
        target=f"target:{sink_type}",
        policy_profile=profile,
        annotations={
            "provenance": {
                "source": source,
                "taint_level": taint_level,
            },
            "input_class": taint_level,
        },
        trust_level=taint_level,
    )


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.case_id) for case in generate_isolation_cases()],
)
def test_cross_session_isolation_generated(case: IsolationCase, tmp_path: Path) -> None:
    root = tmp_path / case.case_id
    session_a = AgentSession(
        session_id=f"A_{case.index:02d}",
        profile=case.profile_a,
        persistence_root=root,
    )
    session_b = AgentSession(
        session_id=f"B_{case.index:02d}",
        profile=case.profile_b,
        persistence_root=root,
    )

    assert session_a.log_path != session_b.log_path
    assert session_b.escalation_score == 0.0
    assert session_b.chain_detector.summary()["events"] == 0

    req_a = f"req-A-{uuid.uuid4().hex[:8]}"
    source_a = f"source_A_{case.index:02d}"
    enriched_a = session_a.evaluate(
        _decision(
            request_id=req_a,
            sink_type=case.sink_type,
            decision=case.decision_a,
            taint_level=case.taint_level,
            source=source_a,
            profile=case.profile_a,
        )
    )
    assert enriched_a.annotations["session"]["session_id"] == session_a.session_id
    assert enriched_a.annotations["session"]["source_id"] == source_a

    if case.close_a_before_b:
        session_a.close()

    # Session B must start from a clean state regardless of session A history.
    assert session_b.escalation_score == 0.0
    assert len(session_b.decisions) == 0
    assert session_b.chain_detector.summary()["events"] == 0

    req_b = f"req-B-{uuid.uuid4().hex[:8]}"
    source_b = f"source_B_{case.index:02d}"
    enriched_b = session_b.evaluate(
        _decision(
            request_id=req_b,
            sink_type="tool.custom",
            decision="allow",
            taint_level="trusted",
            source=source_b,
            profile=case.profile_b,
        )
    )

    session_meta_b = enriched_b.annotations["session"]
    assert session_meta_b["session_id"] == session_b.session_id
    assert session_meta_b["call_index"] == 1
    assert session_meta_b["source_id"] == source_b
    assert session_meta_b["chain_detections"] == []
    assert session_b.chain_detector.summary()["events"] == 1

    # JSONL logs stay isolated per session and never mix request ids.
    a_lines = session_a.log_path.read_text(encoding="utf-8").splitlines()
    b_lines = session_b.log_path.read_text(encoding="utf-8").splitlines()
    assert any(req_a in line for line in a_lines)
    assert all(req_b not in line for line in a_lines)
    assert any(req_b in line for line in b_lines)
    assert all(req_a not in line for line in b_lines)
