"""
Temporal chain detection for multi-step exploit sequences.

Signal weighting (in order of reliability):
1. Untrusted taint continuity — primary signal
2. Sink risk progression — secondary signal
3. Velocity anomaly — tertiary signal
4. Same source burst — supporting only
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ChainPattern(str, Enum):
    """Structural chain patterns for session-level risk detection."""

    TAINT_CONTINUITY = "taint_continuity"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    VELOCITY_ANOMALY = "velocity_anomaly"
    SAME_SOURCE_BURST = "same_source_burst"


CHAIN_THRESHOLDS: dict[str, dict[str, int | float]] = {
    "dev_balanced": {
        "window_seconds": 60,
        "min_untrusted_count": 3,
        "velocity_multiplier": 10,
    },
    "dev_strict": {
        "window_seconds": 30,
        "min_untrusted_count": 2,
        "velocity_multiplier": 5,
    },
    "prod_locked": {
        "window_seconds": 10,
        "min_untrusted_count": 2,
        "velocity_multiplier": 3,
    },
}

SINK_RISK_LEVEL: dict[str, int] = {
    "tool.custom": 1,
    "filesystem.read": 1,
    "http.request": 2,
    "filesystem.write": 3,
    "credentials.access": 4,
    "shell.exec": 4,
}

PATTERN_BASE_RISK_DELTA: dict[ChainPattern, float] = {
    ChainPattern.TAINT_CONTINUITY: 1.5,
    ChainPattern.PRIVILEGE_ESCALATION: 2.0,
    ChainPattern.VELOCITY_ANOMALY: 1.25,
    ChainPattern.SAME_SOURCE_BURST: 0.75,
}


@dataclass(frozen=True)
class ChainDetectionResult:
    pattern: ChainPattern
    confidence: float
    evidence: list[str]
    time_window: timedelta
    risk_delta: float
    primary_signal: str


@dataclass(frozen=True)
class DecisionEvent:
    decision_id: str
    timestamp: datetime
    sink_type: str
    taint_level: str
    source_id: str


class ChainDetector:
    """Session chain detector with profile-tuned thresholds."""

    def __init__(self, session_id: str, profile: str) -> None:
        self.session_id = session_id
        self.profile = profile if profile in CHAIN_THRESHOLDS else "dev_balanced"
        self._events: list[DecisionEvent] = []

    @property
    def events(self) -> list[DecisionEvent]:
        return list(self._events)

    def observe(
        self,
        *,
        decision_id: str,
        sink_type: str,
        taint_level: str,
        source_id: str,
        timestamp: datetime | None = None,
    ) -> list[ChainDetectionResult]:
        """Observe a decision and return newly detected chain signals."""
        event_time = timestamp or datetime.now(timezone.utc)
        normalized = DecisionEvent(
            decision_id=decision_id,
            timestamp=event_time.astimezone(timezone.utc),
            sink_type=str(sink_type or "tool.custom"),
            taint_level=str(taint_level or "unknown").lower(),
            source_id=str(source_id or "unknown_source"),
        )
        self._events.append(normalized)
        return self.detect()

    def detect(self) -> list[ChainDetectionResult]:
        """Detect chain patterns in the active profile window."""
        if not self._events:
            return []

        threshold = CHAIN_THRESHOLDS[self.profile]
        window_seconds = int(threshold["window_seconds"])
        min_untrusted = int(threshold["min_untrusted_count"])
        velocity_multiplier = float(threshold["velocity_multiplier"])

        latest = self._events[-1].timestamp
        window_start = latest - timedelta(seconds=window_seconds)
        in_window = [e for e in self._events if e.timestamp >= window_start]

        results: list[ChainDetectionResult] = []
        taint_result = self._detect_taint_continuity(in_window, min_untrusted, window_seconds)
        if taint_result is not None:
            results.append(taint_result)

        escalation_result = self._detect_privilege_escalation(in_window, window_seconds)
        if escalation_result is not None:
            results.append(escalation_result)

        velocity_result = self._detect_velocity_anomaly(
            in_window,
            window_seconds,
            velocity_multiplier=velocity_multiplier,
        )
        if velocity_result is not None:
            results.append(velocity_result)

        source_result = self._detect_same_source_burst(in_window, min_untrusted, window_seconds)
        if source_result is not None:
            results.append(source_result)

        return results

    @staticmethod
    def _confidence(value: float) -> float:
        return max(0.0, min(value, 1.0))

    @staticmethod
    def _risk(sink_type: str) -> int:
        return SINK_RISK_LEVEL.get(str(sink_type or "tool.custom"), 1)

    def _detect_taint_continuity(
        self,
        in_window: list[DecisionEvent],
        min_untrusted: int,
        window_seconds: int,
    ) -> ChainDetectionResult | None:
        untrusted = [e for e in in_window if e.taint_level == "untrusted"]
        if len(untrusted) < min_untrusted:
            return None

        confidence = self._confidence(0.6 + ((len(untrusted) - min_untrusted) * 0.1))
        risk_delta = PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * confidence
        return ChainDetectionResult(
            pattern=ChainPattern.TAINT_CONTINUITY,
            confidence=confidence,
            evidence=[e.decision_id for e in untrusted[-min_untrusted:]],
            time_window=timedelta(seconds=window_seconds),
            risk_delta=round(risk_delta, 3),
            primary_signal=(
                f"{len(untrusted)} untrusted decisions within {window_seconds}s "
                "(source-independent)"
            ),
        )

    def _detect_privilege_escalation(
        self,
        in_window: list[DecisionEvent],
        window_seconds: int,
    ) -> ChainDetectionResult | None:
        if len(in_window) < 2:
            return None

        ordered = sorted(in_window, key=lambda e: e.timestamp)
        low_index = None
        critical_index = None
        evidence: list[str] = []

        for idx, event in enumerate(ordered):
            risk = self._risk(event.sink_type)
            if low_index is None and risk <= 2:
                low_index = idx
            if low_index is not None and idx > low_index and risk >= 4:
                critical_index = idx
                break

        if low_index is None or critical_index is None:
            return None

        for event in ordered[low_index : critical_index + 1]:
            evidence.append(event.decision_id)

        confidence = self._confidence(0.65 + (0.05 * max(0, len(evidence) - 2)))
        risk_delta = PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * confidence
        return ChainDetectionResult(
            pattern=ChainPattern.PRIVILEGE_ESCALATION,
            confidence=confidence,
            evidence=evidence,
            time_window=timedelta(seconds=window_seconds),
            risk_delta=round(risk_delta, 3),
            primary_signal="sink risk progression from low/medium to critical",
        )

    def _detect_velocity_anomaly(
        self,
        in_window: list[DecisionEvent],
        window_seconds: int,
        *,
        velocity_multiplier: float,
    ) -> ChainDetectionResult | None:
        if len(in_window) < 2:
            return None

        latest = in_window[-1].timestamp
        window_start = latest - timedelta(seconds=window_seconds)
        prior_events = [e for e in self._events if e.timestamp < window_start]
        if len(prior_events) < 3:
            return None

        current_rate = len(in_window) / float(max(window_seconds, 1))
        baseline_duration = max(
            (prior_events[-1].timestamp - prior_events[0].timestamp).total_seconds(),
            1.0,
        )
        baseline_rate = len(prior_events) / baseline_duration
        if baseline_rate <= 0:
            return None

        ratio = current_rate / baseline_rate
        if ratio < velocity_multiplier:
            return None

        confidence = self._confidence(0.55 + min((ratio / velocity_multiplier) * 0.2, 0.35))
        risk_delta = PATTERN_BASE_RISK_DELTA[ChainPattern.VELOCITY_ANOMALY] * confidence
        return ChainDetectionResult(
            pattern=ChainPattern.VELOCITY_ANOMALY,
            confidence=confidence,
            evidence=[event.decision_id for event in in_window[-min(5, len(in_window)) :]],
            time_window=timedelta(seconds=window_seconds),
            risk_delta=round(risk_delta, 3),
            primary_signal=f"event velocity {ratio:.2f}x baseline",
        )

    def _detect_same_source_burst(
        self,
        in_window: list[DecisionEvent],
        min_untrusted: int,
        window_seconds: int,
    ) -> ChainDetectionResult | None:
        if len(in_window) < min_untrusted:
            return None

        counts: dict[str, list[DecisionEvent]] = {}
        for event in in_window:
            if event.taint_level != "untrusted":
                continue
            counts.setdefault(event.source_id, []).append(event)

        if not counts:
            return None

        source_id, burst = max(counts.items(), key=lambda item: len(item[1]))
        if len(burst) < min_untrusted:
            return None

        confidence = self._confidence(0.45 + ((len(burst) - min_untrusted) * 0.08))
        risk_delta = PATTERN_BASE_RISK_DELTA[ChainPattern.SAME_SOURCE_BURST] * confidence
        return ChainDetectionResult(
            pattern=ChainPattern.SAME_SOURCE_BURST,
            confidence=confidence,
            evidence=[e.decision_id for e in burst[-min_untrusted:]],
            time_window=timedelta(seconds=window_seconds),
            risk_delta=round(risk_delta, 3),
            primary_signal=f"same source burst from {source_id}",
        )

    def reset(self) -> None:
        self._events = []

    def summary(self) -> dict[str, Any]:
        detections = self.detect()
        return {
            "session_id": self.session_id,
            "profile": self.profile,
            "events": len(self._events),
            "detections": [
                {
                    "pattern": detection.pattern.value,
                    "confidence": detection.confidence,
                    "risk_delta": detection.risk_delta,
                    "primary_signal": detection.primary_signal,
                    "evidence": detection.evidence,
                }
                for detection in detections
            ],
        }
