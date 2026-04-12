"""Session chain pattern detector tests."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.runtime.chain_patterns import (
    CHAIN_THRESHOLDS,
    ChainDetector,
    ChainPattern,
)


def _observe(
    detector: ChainDetector,
    *,
    index: int,
    ts: datetime,
    sink: str = "tool.custom",
    taint: str = "trusted",
    source: str = "src",
) -> None:
    detector.observe(
        decision_id=f"d{index}",
        sink_type=sink,
        taint_level=taint,
        source_id=source,
        timestamp=ts,
    )


def test_threshold_profiles_present() -> None:
    assert set(CHAIN_THRESHOLDS) == {"dev_balanced", "dev_strict", "prod_locked"}


def test_unknown_profile_falls_back_to_dev_balanced() -> None:
    detector = ChainDetector(session_id="s1", profile="invalid")
    assert detector.profile == "dev_balanced"


def test_empty_session_has_no_detections() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    assert detector.detect() == []


def test_single_event_has_no_detections() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    now = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=now, taint="untrusted")
    assert detector.detect() == []


def test_taint_continuity_detects_with_fragmented_sources() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), taint="untrusted", source="c")
    detections = detector.detect()
    assert any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in detections)


def test_same_source_burst_not_required_for_taint_continuity() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="x")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="y")
    detections = detector.detect()
    assert any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in detections)
    assert not any(d.pattern == ChainPattern.SAME_SOURCE_BURST for d in detections)


def test_same_source_burst_detects_when_source_repeats() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_strict")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="same")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="same")
    detections = detector.detect()
    assert any(d.pattern == ChainPattern.SAME_SOURCE_BURST for d in detections)


def test_privilege_escalation_detects_low_to_critical_sequence() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, sink="filesystem.read", taint="trusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="http.request", taint="trusted")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), sink="shell.exec", taint="trusted")
    detections = detector.detect()
    assert any(d.pattern == ChainPattern.PRIVILEGE_ESCALATION for d in detections)


def test_privilege_escalation_not_detected_without_critical_sink() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, sink="filesystem.read")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="http.request")
    assert not any(d.pattern == ChainPattern.PRIVILEGE_ESCALATION for d in detector.detect())


def test_velocity_anomaly_detects_relative_spike() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_strict")
    t0 = datetime.now(timezone.utc)
    # Baseline: 3 sparse events far outside the future spike window.
    _observe(detector, index=1, ts=t0)
    _observe(detector, index=2, ts=t0 + timedelta(seconds=300))
    _observe(detector, index=3, ts=t0 + timedelta(seconds=600))
    # Spike: 3 events in 2 seconds inside current 30s window.
    _observe(detector, index=4, ts=t0 + timedelta(seconds=1000))
    _observe(detector, index=5, ts=t0 + timedelta(seconds=1001))
    _observe(detector, index=6, ts=t0 + timedelta(seconds=1002))
    detections = detector.detect()
    assert any(d.pattern == ChainPattern.VELOCITY_ANOMALY for d in detections)


def test_velocity_anomaly_needs_baseline_history() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0)
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1))
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2))
    assert not any(d.pattern == ChainPattern.VELOCITY_ANOMALY for d in detector.detect())


def test_profile_thresholds_change_detection_boundary() -> None:
    t0 = datetime.now(timezone.utc)
    balanced = ChainDetector(session_id="s1", profile="dev_balanced")
    strict = ChainDetector(session_id="s2", profile="dev_strict")

    _observe(balanced, index=1, ts=t0, taint="untrusted", source="a")
    _observe(balanced, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    _observe(strict, index=1, ts=t0, taint="untrusted", source="a")
    _observe(strict, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")

    assert not any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in balanced.detect())
    assert any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in strict.detect())


def test_time_window_boundary_excludes_old_decisions() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0 - timedelta(seconds=20), taint="untrusted")
    _observe(detector, index=2, ts=t0, taint="untrusted")
    assert not any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in detector.detect())


def test_confidence_is_bounded_between_zero_and_one() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime.now(timezone.utc)
    for i in range(20):
        _observe(
            detector,
            index=i,
            ts=t0 + timedelta(seconds=i),
            taint="untrusted",
            source=f"s{i}",
        )
    for detection in detector.detect():
        assert 0.0 <= detection.confidence <= 1.0


def test_risk_delta_is_positive_for_each_detection() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_strict")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, sink="filesystem.read", taint="untrusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="shell.exec", taint="untrusted")
    for detection in detector.detect():
        assert detection.risk_delta > 0.0


def test_summary_returns_detection_payload() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    summary = detector.summary()
    assert summary["session_id"] == "s1"
    assert summary["events"] == 2
    assert len(summary["detections"]) >= 1
