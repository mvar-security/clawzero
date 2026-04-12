"""Session runtime state for cross-call correlation and escalation."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clawzero.contracts import ActionDecision
from clawzero.runtime.chain_patterns import ChainDetector, ChainDetectionResult

SINK_ESCALATION_WEIGHTS: dict[str, float] = {
    "shell.exec": 3.0,
    "credentials.access": 3.0,
    "filesystem.write": 2.0,
    "http.request": 1.5,
    "filesystem.read": 1.0,
    "tool.custom": 0.5,
}

ESCALATION_THRESHOLDS: dict[str, float | None] = {
    "dev_balanced": 5.0,
    "dev_strict": 8.0,
    "prod_locked": None,
}

PROFILE_ESCALATION_TARGET: dict[str, str] = {
    "dev_balanced": "dev_strict",
    "dev_strict": "prod_locked",
    "prod_locked": "prod_locked",
}


@dataclass(frozen=True)
class SessionDecisionRecord:
    """Persistable record for one session decision."""

    request_id: str
    timestamp: str
    sink_type: str
    decision: str
    reason_code: str
    taint_level: str
    source_id: str
    escalation_score: float
    profile: str
    chain_patterns: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "sink_type": self.sink_type,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "taint_level": self.taint_level,
            "source_id": self.source_id,
            "escalation_score": self.escalation_score,
            "profile": self.profile,
            "chain_patterns": self.chain_patterns,
        }


class AgentSession:
    """
    Stateful cross-call correlation for one agent run.

    Session state is append-only and isolated by session_id.
    """

    def __init__(
        self,
        session_id: str | None = None,
        profile: str = "dev_balanced",
        *,
        persistence_root: Path | None = None,
    ) -> None:
        self.session_id = session_id or uuid.uuid4().hex
        self.profile = profile if profile in ESCALATION_THRESHOLDS else "dev_balanced"
        self.started_at = datetime.now(timezone.utc)
        self.decisions: list[SessionDecisionRecord] = []
        self.chain_detector = ChainDetector(self.session_id, self.profile)
        self.escalation_score: float = 0.0
        self.witness_chain: list[dict[str, Any]] = []
        root = persistence_root or (_state_root() / "sessions")
        self._log_path = root / f"{self.session_id}.jsonl"
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._closed = False

    @property
    def log_path(self) -> Path:
        return self._log_path

    def evaluate(self, decision: ActionDecision) -> ActionDecision:
        """Enrich a decision with session metadata and chain detections."""
        if self._closed:
            raise RuntimeError("session is closed")

        timestamp = datetime.now(timezone.utc)
        taint_level = self._taint_level(decision)
        source_id = self._source_id(decision)
        detections = self.chain_detector.observe(
            decision_id=decision.request_id,
            sink_type=decision.sink_type,
            taint_level=taint_level,
            source_id=source_id,
            timestamp=timestamp,
        )

        self._update_escalation(decision=decision, taint_level=taint_level, detections=detections)
        escalated_to = self._maybe_escalate_profile()

        chain_pattern_names = [item.pattern.value for item in detections]
        record = SessionDecisionRecord(
            request_id=decision.request_id,
            timestamp=timestamp.isoformat(),
            sink_type=decision.sink_type,
            decision=decision.decision,
            reason_code=decision.reason_code,
            taint_level=taint_level,
            source_id=source_id,
            escalation_score=round(self.escalation_score, 3),
            profile=self.profile,
            chain_patterns=chain_pattern_names,
        )
        self.decisions.append(record)
        self._append_record(record)

        annotations = dict(decision.annotations)
        annotations["session"] = {
            "session_id": self.session_id,
            "call_index": len(self.decisions),
            "profile": self.profile,
            "escalation_score": round(self.escalation_score, 3),
            "taint_level": taint_level,
            "source_id": source_id,
            "chain_detections": [self._detection_payload(item) for item in detections],
            "log_path": self._log_path.as_posix(),
        }
        if escalated_to is not None:
            annotations["session"]["profile_escalated_to"] = escalated_to

        return ActionDecision(
            request_id=decision.request_id,
            decision=decision.decision,
            reason_code=decision.reason_code,
            human_reason=decision.human_reason,
            sink_type=decision.sink_type,
            target=decision.target,
            policy_profile=decision.policy_profile,
            engine=decision.engine,
            policy_id=decision.policy_id,
            trust_level=decision.trust_level,
            witness_id=decision.witness_id,
            annotations=annotations,
        )

    def attach_witness(self, witness: dict[str, Any] | None) -> None:
        """Attach generated witness artifact to the active session."""
        if not isinstance(witness, dict):
            return
        self.witness_chain.append(witness)

    def get_session_report(self) -> dict[str, Any]:
        ended_at = datetime.now(timezone.utc)
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": round((ended_at - self.started_at).total_seconds(), 3),
            "profile": self.profile,
            "escalation_score": round(self.escalation_score, 3),
            "total_calls": len(self.decisions),
            "blocked_calls": sum(1 for item in self.decisions if item.decision == "block"),
            "witness_chain_length": len(self.witness_chain),
            "log_path": self._log_path.as_posix(),
            "chain_detector": self.chain_detector.summary(),
        }

    def close(self) -> dict[str, Any]:
        self._closed = True
        return self.get_session_report()

    def _update_escalation(
        self,
        *,
        decision: ActionDecision,
        taint_level: str,
        detections: list[ChainDetectionResult],
    ) -> None:
        sink_weight = SINK_ESCALATION_WEIGHTS.get(decision.sink_type, 0.5)
        if taint_level == "untrusted":
            self.escalation_score += sink_weight
        if decision.decision == "block":
            self.escalation_score += sink_weight * 0.25
        self.escalation_score += sum(item.risk_delta for item in detections)

    def _maybe_escalate_profile(self) -> str | None:
        threshold = ESCALATION_THRESHOLDS.get(self.profile)
        if threshold is None:
            return None
        if self.escalation_score < threshold:
            return None
        next_profile = PROFILE_ESCALATION_TARGET[self.profile]
        if next_profile == self.profile:
            return None
        self.profile = next_profile
        self.chain_detector.profile = next_profile
        return next_profile

    def _append_record(self, record: SessionDecisionRecord) -> None:
        with self._log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_json(), ensure_ascii=True) + "\n")

    @staticmethod
    def _detection_payload(detection: ChainDetectionResult) -> dict[str, Any]:
        return {
            "pattern": detection.pattern.value,
            "confidence": detection.confidence,
            "evidence": detection.evidence,
            "risk_delta": detection.risk_delta,
            "primary_signal": detection.primary_signal,
            "time_window_seconds": int(detection.time_window.total_seconds()),
        }

    @staticmethod
    def _taint_level(decision: ActionDecision) -> str:
        if decision.trust_level:
            return str(decision.trust_level).lower()
        session_blob = decision.annotations.get("session")
        if isinstance(session_blob, dict):
            taint = str(session_blob.get("taint_level", "")).strip().lower()
            if taint:
                return taint
        provenance = decision.annotations.get("provenance")
        if isinstance(provenance, dict):
            taint = str(provenance.get("taint_level", "")).strip().lower()
            if taint:
                return taint
        input_class = str(decision.annotations.get("input_class", "")).strip().lower()
        if input_class in {"trusted", "pre_authorized", "untrusted"}:
            return input_class
        return "unknown"

    @staticmethod
    def _source_id(decision: ActionDecision) -> str:
        provenance = decision.annotations.get("provenance")
        if isinstance(provenance, dict):
            source = str(provenance.get("source", "")).strip()
            if source:
                return source
        return "unknown_source"


def _state_root() -> Path:
    explicit = os.getenv("CLAWZERO_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path.home() / ".clawzero"
