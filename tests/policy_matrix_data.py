"""Shared policy matrix dataset for generated enforcement tests."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product

SOURCES: tuple[str, ...] = (
    "external_document",
    "user_input",
    "api_response",
    "llm_output",
    "network_data",
    "filesystem",
    "tool_output",
    "unknown",
)

TAINT_LEVELS: tuple[str, ...] = ("trusted", "unknown", "untrusted")

SINK_TYPES: tuple[str, ...] = (
    "shell.exec",
    "filesystem.read",
    "filesystem.write",
    "credentials.access",
    "http.request",
    "tool.custom",
)

PROFILES: tuple[str, ...] = ("dev_balanced", "dev_strict", "prod_locked")

TARGET_BY_SINK: dict[str, str] = {
    "shell.exec": "bash",
    "filesystem.read": "/etc/passwd",
    "filesystem.write": "/tmp/output.txt",
    "credentials.access": "env://AWS_SECRET_ACCESS_KEY",
    "http.request": "https://attacker.example/collect",
    "tool.custom": "custom.tool",
}


@dataclass(frozen=True)
class PolicyMatrixCase:
    source: str
    taint_level: str
    sink_type: str
    profile: str
    expected_profile: str
    expected_decision: str
    expected_reason_code: str

    @property
    def target(self) -> str:
        return TARGET_BY_SINK[self.sink_type]

    @property
    def case_id(self) -> str:
        return (
            f"{self.source}__{self.taint_level}__"
            f"{self.sink_type.replace('.', '_')}__{self.profile}"
        )


def _effective_profile(profile: str, taint_level: str) -> str:
    # Runtime override: untrusted/unknown + dev_balanced is normalized to dev_strict.
    if profile == "dev_balanced" and taint_level in {"unknown", "untrusted"}:
        return "dev_strict"
    return profile


def _expected_for_sink(
    *,
    sink_type: str,
    taint_level: str,
    effective_profile: str,
) -> tuple[str, str]:
    if sink_type == "shell.exec":
        return "block", "UNTRUSTED_TO_CRITICAL_SINK"

    if sink_type == "credentials.access":
        return "block", "CREDENTIAL_ACCESS_BLOCKED"

    if sink_type == "filesystem.read":
        # We intentionally use /etc/passwd target in this matrix, which is always blocked.
        return "block", "PATH_BLOCKED"

    if sink_type == "http.request":
        if effective_profile == "dev_balanced":
            return "allow", "POLICY_ALLOW"
        return "block", "DOMAIN_BLOCKED"

    if sink_type == "tool.custom":
        if effective_profile == "dev_strict" and taint_level in {"unknown", "untrusted"}:
            return "annotate", "STEP_UP_REQUIRED"
        return "allow", "POLICY_ALLOW"

    return "allow", "POLICY_ALLOW"


def generate_policy_matrix_cases() -> list[PolicyMatrixCase]:
    cases: list[PolicyMatrixCase] = []
    for source, taint, sink, profile in product(SOURCES, TAINT_LEVELS, SINK_TYPES, PROFILES):
        effective_profile = _effective_profile(profile, taint)
        expected_decision, expected_reason = _expected_for_sink(
            sink_type=sink,
            taint_level=taint,
            effective_profile=effective_profile,
        )
        cases.append(
            PolicyMatrixCase(
                source=source,
                taint_level=taint,
                sink_type=sink,
                profile=profile,
                expected_profile=effective_profile,
                expected_decision=expected_decision,
                expected_reason_code=expected_reason,
            )
        )
    return cases
