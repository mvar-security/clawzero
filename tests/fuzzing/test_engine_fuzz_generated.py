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
from urllib.parse import urlparse

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

    @property
    def expected_input_class(self) -> str:
        normalized_input = self.input_class.strip().lower()
        if normalized_input in {"trusted", "pre_authorized", "untrusted"}:
            return normalized_input
        normalized_taint = self.taint_level.strip().lower()
        if normalized_taint in {"trusted", "clean"}:
            return "trusted"
        if normalized_taint in {"pre_authorized", "pre-authorized"}:
            return "pre_authorized"
        return "untrusted"


def _random_token(rng: random.Random, *, min_len: int = 4, max_len: int = 64) -> str:
    length = rng.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + "-_.:/?&=%+@!$[]{}()"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _target_for(
    rng: random.Random,
    sink_type: str,
    index: int,
    sink_case_index: int,
) -> str:
    token = _random_token(rng, min_len=8, max_len=80)
    if sink_type == "shell.exec":
        return f"bash -lc \"echo fuzz_{index}; {token}\""
    if sink_type == "filesystem.read":
        candidates = (
            f"/workspace/project/fuzz_{index:04d}.txt",
            f"/etc/passwd::{token}",
            f"/workspace/../../etc/shadow::{token}",
        )
        return candidates[sink_case_index % len(candidates)]
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
    sink_counts = {sink: 0 for sink in SINK_TYPES}
    for index in range(1, CASE_COUNT + 1):
        profile = PROFILES[(index - 1) % len(PROFILES)]
        sink_type = SINK_TYPES[(index - 1) % len(SINK_TYPES)]
        sink_case_index = sink_counts[sink_type]
        sink_counts[sink_type] += 1
        taint_level = TAINT_LEVELS[(index - 1) % len(TAINT_LEVELS)]
        input_class = INPUT_CLASS_VALUES[(index - 1) % len(INPUT_CLASS_VALUES)]
        source = f"fuzz_source_{index:04d}_{_random_token(rng, min_len=4, max_len=10)}"
        target = _target_for(rng, sink_type, index, sink_case_index)
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


def _expected_decision_for(case: FuzzCase) -> tuple[str, str]:
    profile = case.expected_profile

    if case.sink_type == "shell.exec":
        return "block", "UNTRUSTED_TO_CRITICAL_SINK"
    if case.sink_type == "credentials.access":
        return "block", "CREDENTIAL_ACCESS_BLOCKED"
    if case.sink_type == "filesystem.read":
        target = case.target
        target_lower = target.lower()
        has_traversal_signal = any(
            token in target_lower for token in ("../", "..\\", "%2e%2e", "%2f", "%5c", "%32%65", "\x00")
        )
        is_sensitive_target = target_lower.startswith(
            ("/etc/", "/proc/", "/root/", "/home/", "~/.ssh/", "/users/")
        )
        if profile == "dev_balanced":
            if has_traversal_signal or is_sensitive_target:
                return "block", "PATH_BLOCKED"
            return "allow", "ALLOWLIST_MATCH"
        if profile == "dev_strict":
            if (
                not has_traversal_signal
                and not is_sensitive_target
                and target_lower.startswith("/workspace/")
            ):
                return "allow", "ALLOWLIST_MATCH"
            return "block", "PATH_BLOCKED"
        if (
            not has_traversal_signal
            and not is_sensitive_target
            and target_lower.startswith("/workspace/project/")
        ):
            return "allow", "ALLOWLIST_MATCH"
        return "block", "PATH_BLOCKED"
    if case.sink_type == "http.request":
        if profile == "dev_balanced":
            return "allow", "POLICY_ALLOW"
        if profile == "dev_strict":
            return "block", "DOMAIN_BLOCKED"
        hostname = urlparse(case.target).hostname or case.target
        if hostname in {"localhost", "127.0.0.1"}:
            return "allow", "ALLOWLIST_MATCH"
        return "block", "DOMAIN_BLOCKED"
    if case.sink_type == "tool.custom":
        if profile == "dev_strict":
            if case.expected_input_class in {"trusted", "pre_authorized"}:
                return "allow", "POLICY_ALLOW"
            return "annotate", "STEP_UP_REQUIRED"
        if profile == "dev_balanced" and case.expected_input_class == "untrusted":
            return "annotate", "STEP_UP_REQUIRED"
        return "allow", "POLICY_ALLOW"
    return "allow", "POLICY_ALLOW"


def _expected_witness_taint_level(case: FuzzCase) -> str:
    return "trusted" if case.expected_input_class in {"trusted", "pre_authorized"} else "untrusted"


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
            "target": request.target,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "policy_profile": decision.policy_profile,
            "provenance": request.prompt_provenance,
            "witness_signature": "ed25519_stub:fuzz",
        },
    )

    runtime = _runtime(case.profile)
    decision = runtime.evaluate(_request_for(case))
    expected_decision, expected_reason = _expected_decision_for(case)

    assert decision.decision == expected_decision
    assert decision.reason_code == expected_reason
    assert decision.sink_type == case.sink_type
    assert decision.target == case.target
    assert decision.policy_profile == case.expected_profile
    assert decision.annotations.get("effective_policy_profile") == case.expected_profile
    assert decision.annotations.get("input_class") == case.expected_input_class
    witness = runtime.last_witness
    assert isinstance(witness, dict)
    assert witness.get("request_id") == decision.request_id
    assert witness.get("decision") == decision.decision
    assert witness.get("reason_code") == decision.reason_code
    assert witness.get("sink_type") == case.sink_type
    assert witness.get("target") == case.target
    assert witness.get("policy_profile") == case.expected_profile
    provenance = witness.get("provenance")
    assert isinstance(provenance, dict)
    assert provenance.get("source") == case.source
    assert provenance.get("taint_level") == _expected_witness_taint_level(case)
    assert provenance.get("source_chain") == ["fuzz", case.source, case.sink_type]
    assert provenance.get("taint_markers") == list(case.markers)


def test_engine_fuzz_generated_gap_cross_suite_dedup_not_enforced() -> None:
    pytest.skip(
        "Gap (explicit): this legacy fuzz suite now enforces deterministic runtime contracts, "
        "but does not yet enforce deduplication boundaries versus "
        "test_engine_fuzz_extended_generated.py targeted adversarial scenarios."
    )
