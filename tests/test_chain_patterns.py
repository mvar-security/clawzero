"""Session chain pattern detector tests."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.runtime.chain_patterns import (
    CHAIN_THRESHOLDS,
    PATTERN_BASE_RISK_DELTA,
    ChainDetector,
    ChainDetectionResult,
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


def _get_detection(
    detections: list[ChainDetectionResult],
    pattern: ChainPattern,
) -> ChainDetectionResult:
    matches = [item for item in detections if item.pattern == pattern]
    assert len(matches) == 1, f"expected exactly one {pattern.value} detection, got {len(matches)}"
    return matches[0]


def _expected_taint_continuity_confidence(count: int, minimum: int) -> float:
    return max(0.0, min(0.6 + ((count - minimum) * 0.1), 1.0))


def _expected_privilege_confidence(evidence_len: int) -> float:
    return max(0.0, min(0.65 + (0.05 * max(0, evidence_len - 2)), 1.0))


def _expected_velocity_confidence(ratio: float, multiplier: float) -> float:
    return max(0.0, min(0.55 + min((ratio / multiplier) * 0.2, 0.35), 1.0))


def _expected_same_source_confidence(count: int, minimum: int) -> float:
    return max(0.0, min(0.45 + ((count - minimum) * 0.08), 1.0))


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
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), taint="untrusted", source="c")
    detections = detector.detect()
    taint = _get_detection(detections, ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(3, 3)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    assert taint.evidence == ["d1", "d2", "d3"]
    assert taint.primary_signal == "3 untrusted decisions within 60s (source-independent)"
    assert taint.time_window == timedelta(seconds=60)


def test_same_source_burst_not_required_for_taint_continuity() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="x")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="y")
    detections = detector.detect()
    assert len(detections) == 1
    assert {d.pattern for d in detections} == {ChainPattern.TAINT_CONTINUITY}
    taint = _get_detection(detections, ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(2, 2)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    assert taint.evidence == ["d1", "d2"]
    assert taint.primary_signal == "2 untrusted decisions within 10s (source-independent)"
    assert taint.time_window == timedelta(seconds=10)


def test_same_source_burst_detects_when_source_repeats() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_strict")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="same")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="same")
    detections = detector.detect()
    burst = _get_detection(detections, ChainPattern.SAME_SOURCE_BURST)
    expected_conf = _expected_same_source_confidence(2, 2)
    assert burst.confidence == expected_conf
    assert burst.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.SAME_SOURCE_BURST] * expected_conf,
        3,
    )
    assert burst.evidence == ["d1", "d2"]
    assert burst.primary_signal == "same source burst from same"
    assert burst.time_window == timedelta(seconds=30)


def test_privilege_escalation_detects_low_to_critical_sequence() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="filesystem.read", taint="trusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="http.request", taint="trusted")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), sink="shell.exec", taint="trusted")
    detections = detector.detect()
    escalation = _get_detection(detections, ChainPattern.PRIVILEGE_ESCALATION)
    expected_conf = _expected_privilege_confidence(3)
    assert escalation.confidence == expected_conf
    assert escalation.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * expected_conf,
        3,
    )
    assert escalation.evidence == ["d1", "d2", "d3"]
    assert escalation.primary_signal == "sink risk progression from low/medium to critical"
    assert escalation.time_window == timedelta(seconds=60)


def test_privilege_escalation_not_detected_without_critical_sink() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="filesystem.read")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="http.request")
    assert detector.detect() == []


def test_velocity_anomaly_detects_relative_spike() -> None:
    detector = ChainDetector(session_id="s1", profile="dev_strict")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    # Baseline: 3 sparse events far outside the future spike window.
    _observe(detector, index=1, ts=t0)
    _observe(detector, index=2, ts=t0 + timedelta(seconds=300))
    _observe(detector, index=3, ts=t0 + timedelta(seconds=600))
    # Spike: 3 events in 2 seconds inside current 30s window.
    _observe(detector, index=4, ts=t0 + timedelta(seconds=1000))
    _observe(detector, index=5, ts=t0 + timedelta(seconds=1001))
    _observe(detector, index=6, ts=t0 + timedelta(seconds=1002))
    detections = detector.detect()
    velocity = _get_detection(detections, ChainPattern.VELOCITY_ANOMALY)
    expected_conf = _expected_velocity_confidence(20.0, 5.0)
    assert velocity.confidence == expected_conf
    assert velocity.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.VELOCITY_ANOMALY] * expected_conf,
        3,
    )
    assert velocity.evidence == ["d4", "d5", "d6"]
    assert velocity.primary_signal == "event velocity 20.00x baseline"
    assert velocity.time_window == timedelta(seconds=30)


def test_velocity_anomaly_needs_baseline_history() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime.now(timezone.utc)
    _observe(detector, index=1, ts=t0)
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1))
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2))
    assert not any(d.pattern == ChainPattern.VELOCITY_ANOMALY for d in detector.detect())


def test_profile_thresholds_change_detection_boundary() -> None:
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    balanced = ChainDetector(session_id="s1", profile="dev_balanced")
    strict = ChainDetector(session_id="s2", profile="dev_strict")

    _observe(balanced, index=1, ts=t0, taint="untrusted", source="a")
    _observe(balanced, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    _observe(strict, index=1, ts=t0, taint="untrusted", source="a")
    _observe(strict, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")

    assert balanced.detect() == []

    strict_detections = strict.detect()
    assert len(strict_detections) == 1
    assert {d.pattern for d in strict_detections} == {ChainPattern.TAINT_CONTINUITY}
    taint = _get_detection(strict_detections, ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(2, 2)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    assert taint.evidence == ["d1", "d2"]
    assert taint.primary_signal == "2 untrusted decisions within 30s (source-independent)"
    assert taint.time_window == timedelta(seconds=30)


def test_time_window_boundary_excludes_old_decisions() -> None:
    detector = ChainDetector(session_id="s1", profile="prod_locked")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0 - timedelta(seconds=11), taint="untrusted", source="outside")
    _observe(detector, index=2, ts=t0 - timedelta(seconds=10), taint="untrusted", source="boundary")
    _observe(detector, index=3, ts=t0, taint="untrusted", source="latest")
    detections = detector.detect()
    assert len(detections) == 1
    taint = _get_detection(detections, ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(2, 2)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    # Inclusive boundary contract: timestamp == window_start is included.
    assert taint.evidence == ["d2", "d3"]
    assert taint.primary_signal == "2 untrusted decisions within 10s (source-independent)"
    assert taint.time_window == timedelta(seconds=10)


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
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    summary = detector.summary()
    assert summary["session_id"] == "s1"
    assert summary["profile"] == "prod_locked"
    assert summary["events"] == 2
    assert len(summary["detections"]) == 1
    detection = summary["detections"][0]
    assert detection["pattern"] == "taint_continuity"
    assert detection["confidence"] == _expected_taint_continuity_confidence(2, 2)
    assert detection["risk_delta"] == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY]
        * _expected_taint_continuity_confidence(2, 2),
        3,
    )
    assert detection["primary_signal"] == "2 untrusted decisions within 10s (source-independent)"
    assert detection["evidence"] == ["d1", "d2"]


def test_taint_continuity_dev_strict_threshold_2() -> None:
    detector = ChainDetector(session_id="s_dev_strict", profile="dev_strict")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")
    taint = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(2, 2)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    assert taint.evidence == ["d1", "d2"]
    assert taint.primary_signal == "2 untrusted decisions within 30s (source-independent)"


def test_taint_continuity_prod_locked_threshold_2() -> None:
    detector = ChainDetector(session_id="s_prod_locked", profile="prod_locked")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="x")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=2), taint="untrusted", source="y")
    taint = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    expected_conf = _expected_taint_continuity_confidence(2, 2)
    assert taint.confidence == expected_conf
    assert taint.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected_conf,
        3,
    )
    assert taint.time_window == timedelta(seconds=10)


def test_taint_continuity_confidence_scaling() -> None:
    detector = ChainDetector(session_id="s_scaling", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="b")

    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), taint="untrusted", source="c")
    det3 = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    expected3 = _expected_taint_continuity_confidence(3, 3)
    assert det3.confidence == expected3
    assert det3.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected3, 3)

    _observe(detector, index=4, ts=t0 + timedelta(seconds=3), taint="untrusted", source="d")
    det4 = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    expected4 = _expected_taint_continuity_confidence(4, 3)
    assert det4.confidence == expected4
    assert det4.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected4, 3)

    _observe(detector, index=5, ts=t0 + timedelta(seconds=4), taint="untrusted", source="e")
    det5 = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    expected5 = _expected_taint_continuity_confidence(5, 3)
    assert det5.confidence == expected5
    assert det5.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * expected5, 3)


def test_taint_continuity_excluded_outside_window() -> None:
    detector = ChainDetector(session_id="s_window", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0 - timedelta(seconds=180), taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 - timedelta(seconds=170), taint="untrusted", source="b")
    _observe(detector, index=3, ts=t0 - timedelta(seconds=161), taint="untrusted", source="c")
    _observe(detector, index=4, ts=t0 - timedelta(seconds=10), taint="untrusted", source="d")
    _observe(detector, index=5, ts=t0, taint="untrusted", source="e")
    assert not any(d.pattern == ChainPattern.TAINT_CONTINUITY for d in detector.detect())


def test_privilege_escalation_medium_to_critical() -> None:
    detector = ChainDetector(session_id="s_priv_1", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="http.request", taint="trusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="shell.exec", taint="trusted")
    escalation = _get_detection(detector.detect(), ChainPattern.PRIVILEGE_ESCALATION)
    expected_conf = _expected_privilege_confidence(2)
    assert escalation.confidence == expected_conf
    assert escalation.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * expected_conf,
        3,
    )
    assert escalation.evidence == ["d1", "d2"]
    assert escalation.primary_signal == "sink risk progression from low/medium to critical"


def test_privilege_escalation_confidence_by_chain_length() -> None:
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)

    detector2 = ChainDetector(session_id="s_priv_2", profile="dev_balanced")
    _observe(detector2, index=1, ts=t0, sink="http.request", taint="trusted")
    _observe(detector2, index=2, ts=t0 + timedelta(seconds=1), sink="shell.exec", taint="trusted")
    esc2 = _get_detection(detector2.detect(), ChainPattern.PRIVILEGE_ESCALATION)
    expected2 = _expected_privilege_confidence(2)
    assert esc2.confidence == expected2
    assert esc2.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * expected2, 3)

    detector5 = ChainDetector(session_id="s_priv_5", profile="dev_balanced")
    _observe(detector5, index=1, ts=t0, sink="tool.custom", taint="trusted")
    _observe(detector5, index=2, ts=t0 + timedelta(seconds=1), sink="filesystem.read", taint="trusted")
    _observe(detector5, index=3, ts=t0 + timedelta(seconds=2), sink="http.request", taint="trusted")
    _observe(detector5, index=4, ts=t0 + timedelta(seconds=3), sink="filesystem.write", taint="trusted")
    _observe(detector5, index=5, ts=t0 + timedelta(seconds=4), sink="shell.exec", taint="trusted")
    esc5 = _get_detection(detector5.detect(), ChainPattern.PRIVILEGE_ESCALATION)
    expected5 = _expected_privilege_confidence(5)
    assert esc5.confidence == expected5
    assert esc5.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * expected5, 3)


def test_privilege_escalation_evidence_full_chain() -> None:
    detector = ChainDetector(session_id="s_priv_chain", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="tool.custom", taint="trusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="filesystem.read", taint="trusted")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), sink="http.request", taint="trusted")
    _observe(detector, index=4, ts=t0 + timedelta(seconds=3), sink="shell.exec", taint="trusted")
    _observe(detector, index=5, ts=t0 + timedelta(seconds=4), sink="credentials.access", taint="trusted")
    escalation = _get_detection(detector.detect(), ChainPattern.PRIVILEGE_ESCALATION)
    # Evidence is first-low to first-critical, not full in-window coverage.
    assert escalation.evidence == ["d1", "d2", "d3", "d4"]
    expected_conf = _expected_privilege_confidence(4)
    assert escalation.confidence == expected_conf
    assert escalation.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.PRIVILEGE_ESCALATION] * expected_conf,
        3,
    )


def test_privilege_escalation_no_low_prerequisite_fails() -> None:
    detector = ChainDetector(session_id="s_priv_none", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="shell.exec", taint="trusted")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="credentials.access", taint="trusted")
    assert not any(d.pattern == ChainPattern.PRIVILEGE_ESCALATION for d in detector.detect())


def _observe_velocity_profile(
    *,
    profile: str,
    ratio: float,
    base_time: datetime,
) -> ChainDetectionResult:
    detector = ChainDetector(session_id=f"vel_{profile}_{ratio}", profile=profile)
    window_seconds = int(CHAIN_THRESHOLDS[profile]["window_seconds"])
    multiplier = float(CHAIN_THRESHOLDS[profile]["velocity_multiplier"])
    in_window_count = 2
    current_rate = in_window_count / float(window_seconds)
    baseline_rate = current_rate / ratio
    baseline_duration = 3.0 / baseline_rate
    prior_start = base_time - timedelta(seconds=baseline_duration + window_seconds + 10)
    prior_end = prior_start + timedelta(seconds=baseline_duration)

    _observe(detector, index=1, ts=prior_start, sink="tool.custom", taint="trusted", source="baseline_a")
    _observe(
        detector,
        index=2,
        ts=prior_start + (prior_end - prior_start) / 2,
        sink="tool.custom",
        taint="trusted",
        source="baseline_b",
    )
    _observe(detector, index=3, ts=prior_end, sink="tool.custom", taint="trusted", source="baseline_c")
    _observe(detector, index=4, ts=base_time - timedelta(seconds=1), sink="tool.custom", taint="trusted", source="spike_a")
    _observe(detector, index=5, ts=base_time, sink="tool.custom", taint="trusted", source="spike_b")
    detection = _get_detection(detector.detect(), ChainPattern.VELOCITY_ANOMALY)

    expected_conf = _expected_velocity_confidence(ratio, multiplier)
    assert detection.confidence == expected_conf
    assert detection.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.VELOCITY_ANOMALY] * expected_conf,
        3,
    )
    assert detection.primary_signal == f"event velocity {ratio:.2f}x baseline"
    assert detection.evidence == ["d4", "d5"]
    assert detection.time_window == timedelta(seconds=window_seconds)
    return detection


def test_velocity_anomaly_dev_strict_5x_multiplier() -> None:
    _observe_velocity_profile(
        profile="dev_strict",
        ratio=5.0,
        base_time=datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc),
    )


def test_velocity_anomaly_prod_locked_3x_multiplier() -> None:
    _observe_velocity_profile(
        profile="prod_locked",
        ratio=3.0,
        base_time=datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc),
    )


def test_velocity_anomaly_confidence_scaling() -> None:
    base = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    d5 = _observe_velocity_profile(profile="dev_strict", ratio=5.0, base_time=base)
    d10 = _observe_velocity_profile(profile="dev_strict", ratio=10.0, base_time=base + timedelta(hours=1))
    d20 = _observe_velocity_profile(profile="dev_strict", ratio=20.0, base_time=base + timedelta(hours=2))

    expected5 = _expected_velocity_confidence(5.0, 5.0)
    expected10 = _expected_velocity_confidence(10.0, 5.0)
    expected20 = _expected_velocity_confidence(20.0, 5.0)
    assert d5.confidence == expected5
    assert d10.confidence == expected10
    assert d20.confidence == expected20
    assert d10.confidence == d20.confidence
    assert d10.risk_delta == d20.risk_delta


def test_same_source_burst_selects_max_source() -> None:
    detector = ChainDetector(session_id="s_burst_max", profile="dev_strict")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="src_a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="src_b")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), taint="untrusted", source="src_a")
    _observe(detector, index=4, ts=t0 + timedelta(seconds=3), taint="untrusted", source="src_b")
    _observe(detector, index=5, ts=t0 + timedelta(seconds=4), taint="untrusted", source="src_a")
    burst = _get_detection(detector.detect(), ChainPattern.SAME_SOURCE_BURST)
    expected_conf = _expected_same_source_confidence(3, 2)
    assert burst.confidence == expected_conf
    assert burst.risk_delta == round(
        PATTERN_BASE_RISK_DELTA[ChainPattern.SAME_SOURCE_BURST] * expected_conf,
        3,
    )
    assert burst.primary_signal == "same source burst from src_a"
    assert burst.evidence == ["d3", "d5"]


def test_same_source_burst_ignores_trusted() -> None:
    detector = ChainDetector(session_id="s_burst_trusted", profile="dev_strict")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, taint="untrusted", source="same")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), taint="trusted", source="same")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), taint="trusted", source="same")
    assert not any(d.pattern == ChainPattern.SAME_SOURCE_BURST for d in detector.detect())


def test_same_source_burst_confidence_scaling() -> None:
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)

    detector2 = ChainDetector(session_id="s_burst2", profile="dev_strict")
    _observe(detector2, index=1, ts=t0, taint="untrusted", source="same")
    _observe(detector2, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="same")
    burst2 = _get_detection(detector2.detect(), ChainPattern.SAME_SOURCE_BURST)
    expected2 = _expected_same_source_confidence(2, 2)
    assert burst2.confidence == expected2
    assert burst2.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.SAME_SOURCE_BURST] * expected2, 3)

    detector3 = ChainDetector(session_id="s_burst3", profile="dev_strict")
    _observe(detector3, index=1, ts=t0, taint="untrusted", source="same")
    _observe(detector3, index=2, ts=t0 + timedelta(seconds=1), taint="untrusted", source="same")
    _observe(detector3, index=3, ts=t0 + timedelta(seconds=2), taint="untrusted", source="same")
    burst3 = _get_detection(detector3.detect(), ChainPattern.SAME_SOURCE_BURST)
    expected3 = _expected_same_source_confidence(3, 2)
    assert burst3.confidence == expected3
    assert burst3.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.SAME_SOURCE_BURST] * expected3, 3)


def test_multiple_patterns_detected_simultaneously() -> None:
    detector = ChainDetector(session_id="s_multi", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    _observe(detector, index=1, ts=t0, sink="http.request", taint="untrusted", source="a")
    _observe(detector, index=2, ts=t0 + timedelta(seconds=1), sink="filesystem.read", taint="untrusted", source="b")
    _observe(detector, index=3, ts=t0 + timedelta(seconds=2), sink="shell.exec", taint="untrusted", source="c")
    detections = detector.detect()
    patterns = {item.pattern for item in detections}
    assert len(detections) == 2
    assert patterns == {
        ChainPattern.TAINT_CONTINUITY,
        ChainPattern.PRIVILEGE_ESCALATION,
    }


def test_observe_normalizes_to_utc() -> None:
    detector = ChainDetector(session_id="s_utc", profile="dev_balanced")
    ts = datetime(2026, 4, 13, 7, 0, tzinfo=timezone(timedelta(hours=-5)))
    detector.observe(
        decision_id="d1",
        sink_type="tool.custom",
        taint_level="trusted",
        source_id="src",
        timestamp=ts,
    )
    event = detector.events[0]
    assert event.timestamp.tzinfo == timezone.utc
    assert event.timestamp == ts.astimezone(timezone.utc)


def test_observe_normalizes_null_values() -> None:
    detector = ChainDetector(session_id="s_null", profile="dev_balanced")
    detector.observe(
        decision_id="d1",
        sink_type=None,  # type: ignore[arg-type]
        taint_level=None,  # type: ignore[arg-type]
        source_id=None,  # type: ignore[arg-type]
        timestamp=datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc),
    )
    event = detector.events[0]
    assert event.sink_type == "tool.custom"
    assert event.taint_level == "unknown"
    assert event.source_id == "unknown_source"


def test_confidence_clamping_at_1_0() -> None:
    detector = ChainDetector(session_id="s_clamp", profile="dev_balanced")
    t0 = datetime(2026, 4, 13, 12, 0, tzinfo=timezone.utc)
    for index in range(1, 9):
        _observe(
            detector,
            index=index,
            ts=t0 + timedelta(seconds=index),
            taint="untrusted",
            source=f"s{index}",
        )
    taint = _get_detection(detector.detect(), ChainPattern.TAINT_CONTINUITY)
    assert taint.confidence == 1.0
    assert taint.risk_delta == round(PATTERN_BASE_RISK_DELTA[ChainPattern.TAINT_CONTINUITY] * 1.0, 3)
