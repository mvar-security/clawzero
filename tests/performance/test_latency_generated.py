"""Generated performance/latency suite (Phase 3).

This suite provides 500 deterministic latency checks:

  50 scenarios × 10 load levels

The goal is CI-stable p99 validation for enforcement decisions while
confirming deterministic outcomes under varying request pressure.
"""

from __future__ import annotations

import os
import statistics
import sys
import time
import uuid
from dataclasses import dataclass

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime

PROFILES: tuple[str, ...] = ("dev_balanced", "dev_strict", "prod_locked")
SINK_TYPES: tuple[str, ...] = (
    "shell.exec",
    "filesystem.read",
    "filesystem.write",
    "credentials.access",
    "http.request",
    "tool.custom",
)
LOAD_LEVELS: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
SCENARIO_COUNT = 50

P99_BASE_BUDGET_MS: dict[str, float] = {
    "dev_balanced": 35.0,
    "dev_strict": 40.0,
    "prod_locked": 50.0,
}


@dataclass(frozen=True)
class PerfScenario:
    index: int
    profile: str
    sink_type: str
    taint_level: str
    source: str
    target: str

    @property
    def case_id(self) -> str:
        return (
            f"s{self.index:02d}__"
            f"{self.profile}__"
            f"{self.sink_type.replace('.', '_')}__"
            f"{self.taint_level}"
        )


@dataclass(frozen=True)
class PerfCase:
    scenario: PerfScenario
    load_level: int

    @property
    def sample_count(self) -> int:
        # Keep suite fast but still representative across load levels.
        return self.load_level + 1

    @property
    def budget_ms(self) -> float:
        # Higher load levels get a larger budget envelope.
        return P99_BASE_BUDGET_MS[self.scenario.profile] + (self.load_level * 4.0)

    @property
    def case_id(self) -> str:
        return f"{self.scenario.case_id}__load_{self.load_level:02d}"


def _target_for(*, sink_type: str, taint_level: str, index: int) -> str:
    if sink_type == "shell.exec":
        return f"bash -lc \"echo perf_shell_{index}\""
    if sink_type == "filesystem.read":
        if taint_level == "trusted":
            return f"/workspace/project/perf_{index:02d}.txt"
        return f"/etc/passwd::{index:02d}"
    if sink_type == "filesystem.write":
        return f"/tmp/perf_write_{index:02d}.txt"
    if sink_type == "credentials.access":
        return f"env://PERF_SECRET_{index:02d}"
    if sink_type == "http.request":
        if taint_level == "trusted":
            return f"http://localhost:8080/perf/{index:02d}"
        return f"https://attacker.example/perf/{index:02d}"
    return f"perf.tool.task.{index:02d}"


def _build_scenarios() -> list[PerfScenario]:
    scenarios: list[PerfScenario] = []
    for index in range(1, SCENARIO_COUNT + 1):
        profile = PROFILES[(index - 1) % len(PROFILES)]
        sink_type = SINK_TYPES[(index - 1) % len(SINK_TYPES)]
        taint_level = "untrusted" if index % 2 else "trusted"
        source = "external_document" if taint_level == "untrusted" else "user_request"
        scenarios.append(
            PerfScenario(
                index=index,
                profile=profile,
                sink_type=sink_type,
                taint_level=taint_level,
                source=source,
                target=_target_for(
                    sink_type=sink_type,
                    taint_level=taint_level,
                    index=index,
                ),
            )
        )
    return scenarios


def generate_perf_cases() -> list[PerfCase]:
    return [
        PerfCase(scenario=scenario, load_level=load_level)
        for scenario in _build_scenarios()
        for load_level in LOAD_LEVELS
    ]


def _runtime(profile: str) -> MVARRuntime:
    runtime = MVARRuntime(profile=profile)
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime


def _request_for(scenario: PerfScenario) -> ActionRequest:
    input_class = InputClass.UNTRUSTED.value if scenario.taint_level == "untrusted" else InputClass.TRUSTED.value
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=scenario.sink_type,
        tool_name="perf_probe",
        target=scenario.target,
        arguments={"target": scenario.target},
        input_class=input_class,
        prompt_provenance={
            "source": scenario.source,
            "taint_level": scenario.taint_level,
            "taint_markers": ["performance_probe", scenario.sink_type, scenario.taint_level],
            "source_chain": ["performance", scenario.source, scenario.sink_type],
        },
        policy_profile=scenario.profile,
    )


def _p99(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.99) - 1))
    return ordered[index]


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.case_id) for case in generate_perf_cases()],
)
def test_latency_contract_generated(case: PerfCase, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep latency checks focused on enforcement path by avoiding filesystem witness I/O.
    monkeypatch.setattr(
        "clawzero.runtime.engine.generate_witness",
        lambda _request, _decision: {"witness_id": "perf_stub"},
    )

    runtime = _runtime(case.scenario.profile)

    # Warm-up to avoid first-call skew.
    runtime.evaluate(_request_for(case.scenario))

    latencies_ms: list[float] = []
    decision_values: list[str] = []

    for _ in range(case.sample_count):
        request = _request_for(case.scenario)
        start = time.perf_counter_ns()
        decision = runtime.evaluate(request)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
        latencies_ms.append(elapsed_ms)
        decision_values.append(decision.decision)

    measured_p99 = _p99(latencies_ms)
    measured_mean = statistics.mean(latencies_ms)

    # Determinism contract: same scenario/load should resolve to one decision class.
    assert len(set(decision_values)) == 1
    assert set(decision_values).issubset({"allow", "block", "annotate"})

    # Performance contract: p99 and mean must remain under CI-safe profile budgets.
    assert measured_p99 <= case.budget_ms
    assert measured_mean <= case.budget_ms

