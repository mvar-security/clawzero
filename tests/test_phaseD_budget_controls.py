"""Phase D budget and abuse control tests."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime


def _runtime(
    tmp_path: Path,
    *,
    profile: str = "dev_balanced",
    budget_max_cost_usd: float | None = None,
    budget_max_calls_per_window: int | None = None,
    budget_max_calls_per_sink: int | None = None,
    budget_charging_policy: str = "SUCCESS_BASED",
    budget_default_cost_usd: float = 0.0,
) -> MVARRuntime:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    rt = MVARRuntime(
        profile=profile,
        witness_dir=witness_dir,
        budget_max_cost_usd=budget_max_cost_usd,
        budget_max_calls_per_window=budget_max_calls_per_window,
        budget_max_calls_per_sink=budget_max_calls_per_sink,
        budget_charging_policy=budget_charging_policy,
        budget_default_cost_usd=budget_default_cost_usd,
    )
    rt._mvar_available = False
    rt._mvar_governor = None
    rt.engine = "embedded-policy-v0.1"
    rt.policy_id = "mvar-embedded.v0.1"
    return rt


def _request(
    *,
    sink_type: str = "tool.custom",
    input_class: InputClass = InputClass.TRUSTED,
    target: str = "budget.task",
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="phaseD_tool",
        target=target,
        arguments={"target": target},
        input_class=input_class.value,
        prompt_provenance={
            "source": "user_request" if input_class == InputClass.TRUSTED else "external_document",
            "taint_level": "trusted" if input_class == InputClass.TRUSTED else "untrusted",
            "source_chain": ["budget_test", "tool_call"],
            "taint_markers": [] if input_class == InputClass.TRUSTED else ["prompt_injection"],
        },
        policy_profile="dev_balanced",
    )


def test_budget_max_calls_per_window_attempt_based(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        budget_max_calls_per_window=1,
        budget_charging_policy="ATTEMPT_BASED",
    )

    first = rt.evaluate(_request())
    second = rt.evaluate(_request())

    assert first.decision == "allow"
    assert second.decision == "block"
    assert second.reason_code == "BUDGET_LIMIT_EXCEEDED"
    assert "max_calls_per_window" in second.annotations["budget_status"]["exceeded_limits"]


def test_budget_success_based_does_not_charge_blocked_attempts(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        profile="prod_locked",
        budget_max_calls_per_window=1,
        budget_charging_policy="SUCCESS_BASED",
    )

    req = _request(
        sink_type="shell.exec",
        input_class=InputClass.UNTRUSTED,
        target="bash",
    )

    first = rt.evaluate(req)
    second = rt.evaluate(req)

    assert first.decision == "block"
    assert first.reason_code == "UNTRUSTED_TO_CRITICAL_SINK"
    assert second.decision == "block"
    assert second.reason_code == "UNTRUSTED_TO_CRITICAL_SINK"
    assert second.annotations["budget_status"]["charge_applied"] is False
    assert second.annotations["budget_status"]["calls_total"] == 0


def test_budget_max_calls_per_sink(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        budget_max_calls_per_sink=1,
        budget_charging_policy="ATTEMPT_BASED",
    )

    first = rt.evaluate(_request(sink_type="tool.custom", target="sink.a"))
    second = rt.evaluate(_request(sink_type="tool.custom", target="sink.a"))
    third = rt.evaluate(_request(sink_type="filesystem.read", target="/workspace/doc.txt"))

    assert first.decision == "allow"
    assert second.decision == "block"
    assert second.reason_code == "BUDGET_LIMIT_EXCEEDED"
    assert "max_calls_per_sink" in second.annotations["budget_status"]["exceeded_limits"]
    assert third.decision in {"allow", "block"}


def test_budget_max_cost_usd_and_witness_metadata(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        budget_max_cost_usd=1.0,
        budget_charging_policy="ATTEMPT_BASED",
        budget_default_cost_usd=0.6,
    )

    first = rt.evaluate(_request(target="cost.1"))
    second = rt.evaluate(_request(target="cost.2"))

    assert first.decision == "allow"
    assert second.decision == "block"
    assert second.reason_code == "BUDGET_LIMIT_EXCEEDED"
    assert "max_cost_usd" in second.annotations["budget_status"]["exceeded_limits"]

    witness = rt.last_witness
    assert witness is not None
    assert witness["budget_status"]["enabled"] is True
    assert witness["budget_status"]["charging_policy"] == "ATTEMPT_BASED"
    assert "max_cost_usd" in witness["budget_status"]["exceeded_limits"]
