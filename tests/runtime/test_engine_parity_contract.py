"""Engine parity contract tests for mvar vs embedded execution modes."""

from __future__ import annotations

import os
import sys
import uuid

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime


def _request(
    *,
    sink_type: str,
    target: str,
    taint_level: str,
    input_class: str | None = None,
) -> ActionRequest:
    cls = input_class or ("untrusted" if taint_level != "trusted" else "trusted")
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="parity_tool",
        target=target,
        arguments={"target": target},
        input_class=cls,
        prompt_provenance={
            "source": "external_document" if taint_level != "trusted" else "user_request",
            "taint_level": taint_level,
            "source_chain": ["engine_parity", "tool_call"],
            "taint_markers": [] if taint_level == "trusted" else ["external_content"],
        },
        policy_profile="prod_locked",
        metadata={"adapter": {"name": "parity", "framework": "runtime", "mode": "contract"}},
    )


def test_engine_mode_contract() -> None:
    mode = os.getenv("CLAWZERO_ENGINE_MODE", "").strip().lower()
    runtime = MVARRuntime(profile="prod_locked")

    if mode in {"embedded", "fallback", "force_embedded"}:
        assert runtime.engine == "embedded-policy-v0.1"
        assert runtime.policy_id.startswith("mvar-embedded")
        return

    if mode == "mvar":
        assert runtime.engine == "mvar-security"
        assert runtime.policy_id.startswith("mvar-security")
        return

    # Default developer mode: either engine is acceptable, but must be one of the two.
    assert runtime.engine in {"embedded-policy-v0.1", "mvar-security"}


@pytest.mark.parametrize("profile", ["dev_balanced", "dev_strict", "prod_locked"])
def test_untrusted_shell_exec_blocks_in_all_engine_modes(profile: str) -> None:
    runtime = MVARRuntime(profile=profile)
    decision = runtime.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash -lc \"id\"",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED.value,
        )
    )
    assert decision.decision == "block"
    assert decision.reason_code in {"UNTRUSTED_TO_CRITICAL_SINK", "POLICY_BLOCK", "STEP_UP_REQUIRED"}


@pytest.mark.parametrize("profile", ["dev_balanced", "prod_locked"])
def test_trusted_tool_custom_is_not_hard_blocked(profile: str) -> None:
    runtime = MVARRuntime(profile=profile)
    decision = runtime.evaluate(
        _request(
            sink_type="tool.custom",
            target="tool.safe.operation",
            taint_level="trusted",
            input_class=InputClass.TRUSTED.value,
        )
    )
    assert decision.decision in {"allow", "annotate"}


def test_witness_emission_contract_in_all_modes() -> None:
    runtime = MVARRuntime(profile="prod_locked")
    decision = runtime.evaluate(
        _request(
            sink_type="filesystem.read",
            target="/workspace/project/report.md",
            taint_level="trusted",
            input_class=InputClass.TRUSTED.value,
        )
    )
    assert decision.decision in {"allow", "annotate", "block"}
    witness = runtime.last_witness
    assert isinstance(witness, dict)
    signature = str(witness.get("witness_signature", ""))
    assert signature.startswith("ed25519:") or signature.startswith("ed25519_stub:")
