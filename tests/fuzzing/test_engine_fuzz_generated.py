"""Generated fuzzing corpus for MVARRuntime (Phase 4).

This suite runs 1,000 deterministic fuzz cases against the runtime
contract and asserts core safety invariants:

  - evaluate() never crashes
  - decision class is always valid
  - reason code is always present
  - sink/profile metadata remains coherent
  - witness artifact is always generated
"""

from __future__ import annotations

import os
import random
import string
import sys
import uuid
from dataclasses import dataclass

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src"))

from clawzero.contracts import ActionRequest
from clawzero.runtime import MVARRuntime

CASE_COUNT = 1000
PROFILES: tuple[str, ...] = ("dev_balanced", "dev_strict", "prod_locked")
SINK_TYPES: tuple[str, ...] = (
    "shell.exec",
    "filesystem.read",
    "filesystem.write",
    "credentials.access",
    "http.request",
    "tool.custom",
)
TAINT_LEVELS: tuple[str, ...] = ("trusted", "unknown", "untrusted")
INPUT_CLASS_VALUES: tuple[str, ...] = (
    "trusted",
    "pre_authorized",
    "untrusted",
    "unknown",
    "",
)


@dataclass(frozen=True)
class FuzzCase:
    index: int
    profile: str
    sink_type: str
    taint_level: str
    input_class: str
    source: str
    target: str
    markers: tuple[str, ...]

    @property
    def case_id(self) -> str:
        ic = self.input_class if self.input_class else "empty"
        return (
            f"f{self.index:04d}__"
            f"{self.profile}__"
            f"{self.sink_type.replace('.', '_')}__"
            f"{self.taint_level}__"
            f"ic_{ic}"
        )

    @property
    def expected_profile(self) -> str:
        # Runtime normalization: UNTRUSTED class + dev_balanced => dev_strict.
        # unknown input class resolves to untrusted.
        normalized_input = self.input_class.strip().lower()
        if normalized_input in {"", "unknown"} and self.taint_level not in {"trusted", "pre_authorized"}:
            normalized_input = "untrusted"
        if normalized_input == "untrusted" and self.profile == "dev_balanced":
            return "dev_strict"
        return self.profile


def _random_token(rng: random.Random, *, min_len: int = 4, max_len: int = 64) -> str:
    length = rng.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + "-_.:/?&=%+@!$[]{}()"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _target_for(rng: random.Random, sink_type: str, index: int) -> str:
    token = _random_token(rng, min_len=8, max_len=80)
    if sink_type == "shell.exec":
        return f"bash -lc \"echo fuzz_{index}; {token}\""
    if sink_type == "filesystem.read":
        candidates = (
            f"/workspace/project/fuzz_{index:04d}.txt",
            f"/etc/passwd::{token}",
            f"/workspace/../../etc/shadow::{token}",
        )
        return candidates[index % len(candidates)]
    if sink_type == "filesystem.write":
        return f"/tmp/fuzz_write_{index:04d}_{token[:12]}.txt"
    if sink_type == "credentials.access":
        return f"env://FUZZ_{index:04d}_{token[:24]}"
    if sink_type == "http.request":
        if index % 5 == 0:
            return f"http://localhost:8080/fuzz/{index:04d}?q={token[:16]}"
        return f"https://attacker.example/fuzz/{index:04d}?q={token[:24]}"
    return f"tool.fuzz.{index:04d}.{token[:24]}"


def _build_cases() -> list[FuzzCase]:
    rng = random.Random(20260412)
    cases: list[FuzzCase] = []
    for index in range(1, CASE_COUNT + 1):
        profile = PROFILES[(index - 1) % len(PROFILES)]
        sink_type = SINK_TYPES[(index - 1) % len(SINK_TYPES)]
        taint_level = TAINT_LEVELS[(index - 1) % len(TAINT_LEVELS)]
        input_class = INPUT_CLASS_VALUES[(index - 1) % len(INPUT_CLASS_VALUES)]
        source = f"fuzz_source_{index:04d}_{_random_token(rng, min_len=4, max_len=10)}"
        target = _target_for(rng, sink_type, index)
        markers = (
            "fuzzing",
            sink_type.replace(".", "_"),
            f"case_{index:04d}",
            _random_token(rng, min_len=4, max_len=10),
        )
        cases.append(
            FuzzCase(
                index=index,
                profile=profile,
                sink_type=sink_type,
                taint_level=taint_level,
                input_class=input_class,
                source=source,
                target=target,
                markers=markers,
            )
        )
    return cases


def _runtime(profile: str) -> MVARRuntime:
    runtime = MVARRuntime(profile=profile)
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime


def _request_for(case: FuzzCase) -> ActionRequest:
    provenance = {
        "source": case.source,
        "taint_level": case.taint_level,
        "taint_markers": list(case.markers),
        "source_chain": ["fuzz", case.source, case.sink_type],
    }
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=case.sink_type,
        tool_name="fuzz_tool",
        target=case.target,
        arguments={
            "target": case.target,
            "payload": _random_token(random.Random(case.index), min_len=8, max_len=40),
            "index": case.index,
        },
        input_class=case.input_class,
        prompt_provenance=provenance,
        policy_profile=case.profile,
    )


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.case_id) for case in _build_cases()],
)
def test_engine_fuzz_corpus_generated(case: FuzzCase, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep fuzzing focused on runtime behavior by skipping filesystem witness writes.
    monkeypatch.setattr(
        "clawzero.runtime.engine.generate_witness",
        lambda request, decision: {
            "request_id": request.request_id,
            "sink_type": request.sink_type,
            "decision": decision.decision,
            "witness_signature": "ed25519_stub:fuzz",
        },
    )

    runtime = _runtime(case.profile)
    decision = runtime.evaluate(_request_for(case))

    assert decision.decision in {"allow", "block", "annotate"}
    assert bool(decision.reason_code)
    assert decision.sink_type == case.sink_type
    assert decision.annotations.get("effective_policy_profile") == case.expected_profile
    assert decision.annotations.get("input_class") in {"trusted", "pre_authorized", "untrusted"}
    assert isinstance(runtime.last_witness, dict)
    assert runtime.last_witness.get("decision") == decision.decision
    assert runtime.last_witness.get("sink_type") == case.sink_type

