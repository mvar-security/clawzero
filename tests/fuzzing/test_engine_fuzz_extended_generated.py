"""Extended deterministic fuzz matrix for MVARRuntime.

Adds 1,008 additional runtime robustness scenarios to close out the
large-scale contract surface:
  - source/taint/provenance-shape permutations
  - sink/profile/input-class permutations
  - target pattern and metadata permutations
"""

from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass
from itertools import islice, product

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero.contracts import ActionRequest
from clawzero.runtime import MVARRuntime

CASE_COUNT = 1008
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
INPUT_CLASS_VALUES: tuple[str, ...] = ("trusted", "pre_authorized", "untrusted", "unknown")
TARGET_KINDS: tuple[str, ...] = (
    "local_path",
    "traversal_path",
    "http_url",
    "loopback_url",
    "env_secret",
    "command",
    "custom_symbol",
)
SOURCE_VARIANTS: tuple[str, ...] = (
    "external_document",
    "user_request",
    "api_response",
    "tool_output",
)


@dataclass(frozen=True)
class ExtendedFuzzCase:
    index: int
    profile: str
    sink_type: str
    taint_level: str
    input_class: str
    source: str
    target_kind: str

    @property
    def case_id(self) -> str:
        return (
            f"xf{self.index:04d}__{self.profile}__{self.sink_type.replace('.', '_')}__"
            f"{self.taint_level}__{self.input_class}__{self.target_kind}"
        )


def _target_for(case: ExtendedFuzzCase) -> str:
    idx = case.index
    if case.target_kind == "local_path":
        return f"/workspace/data/input_{idx:04d}.txt"
    if case.target_kind == "traversal_path":
        return f"/workspace/../../etc/passwd::{idx:04d}"
    if case.target_kind == "http_url":
        return f"https://attacker.example/fuzz/{idx:04d}"
    if case.target_kind == "loopback_url":
        return f"http://localhost:8080/fuzz/{idx:04d}"
    if case.target_kind == "env_secret":
        return f"env://FAKE_SECRET_{idx:04d}"
    if case.target_kind == "command":
        return f"bash -lc \"echo fuzz_{idx:04d}\""
    return f"tool.symbol.{idx:04d}"


def _effective_profile(case: ExtendedFuzzCase) -> str:
    normalized_input = case.input_class.strip().lower()
    if normalized_input in {"", "unknown"} and case.taint_level not in {"trusted", "pre_authorized"}:
        normalized_input = "untrusted"
    if normalized_input == "untrusted" and case.profile == "dev_balanced":
        return "dev_strict"
    return case.profile


def _build_cases() -> list[ExtendedFuzzCase]:
    combos = product(PROFILES, SINK_TYPES, TAINT_LEVELS, INPUT_CLASS_VALUES, SOURCE_VARIANTS, TARGET_KINDS)
    cases: list[ExtendedFuzzCase] = []
    for index, (profile, sink, taint, input_class, source, target_kind) in enumerate(
        islice(combos, CASE_COUNT),
        start=1,
    ):
        cases.append(
            ExtendedFuzzCase(
                index=index,
                profile=profile,
                sink_type=sink,
                taint_level=taint,
                input_class=input_class,
                source=source,
                target_kind=target_kind,
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


def _request_for(case: ExtendedFuzzCase) -> ActionRequest:
    target = _target_for(case)
    source_chain = [case.source, f"stage_{case.index % 5}", case.sink_type]
    taint_markers = [] if case.taint_level == "trusted" else ["external_content", f"case_{case.index:04d}"]
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=case.sink_type,
        tool_name=f"fuzz_tool_{case.index % 13}",
        target=target,
        arguments={
            "target": target,
            "index": case.index,
            "metadata": {
                "source_variant": case.source,
                "target_kind": case.target_kind,
                "padding": "x" * ((case.index % 16) + 1),
            },
        },
        input_class=case.input_class,
        prompt_provenance={
            "source": case.source,
            "taint_level": case.taint_level,
            "taint_markers": taint_markers,
            "source_chain": source_chain,
        },
        policy_profile=case.profile,
        metadata={
            "adapter": {
                "name": "fuzz_extended",
                "framework": "matrix",
                "mode": "generated",
            }
        },
    )


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.case_id) for case in _build_cases()],
)
def test_engine_fuzz_extended_generated(case: ExtendedFuzzCase, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "clawzero.runtime.engine.generate_witness",
        lambda request, decision: {
            "request_id": request.request_id,
            "sink_type": request.sink_type,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "witness_signature": "ed25519_stub:extendedfuzz",
        },
    )

    runtime = _runtime(case.profile)
    decision = runtime.evaluate(_request_for(case))

    assert decision.decision in {"allow", "block", "annotate"}
    assert bool(decision.reason_code)
    assert decision.sink_type == case.sink_type
    assert decision.policy_profile == _effective_profile(case)
    assert decision.annotations.get("effective_policy_profile") == _effective_profile(case)
    assert decision.annotations.get("input_class") in {"trusted", "pre_authorized", "untrusted"}
    assert isinstance(runtime.last_witness, dict)
    assert runtime.last_witness.get("decision") == decision.decision
    assert runtime.last_witness.get("sink_type") == case.sink_type
