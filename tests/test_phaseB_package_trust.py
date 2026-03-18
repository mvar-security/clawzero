"""Phase B package trust tests: marketplace signature and publisher enforcement."""

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
    profile: str,
    trusted_publishers: list[str] | None = None,
) -> MVARRuntime:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    rt = MVARRuntime(
        profile=profile,
        witness_dir=witness_dir,
        trusted_publishers=trusted_publishers or [],
    )
    rt._mvar_available = False
    rt._mvar_governor = None
    rt.engine = "embedded-policy-v0.1"
    rt.policy_id = "mvar-embedded.v0.1"
    return rt


def _request(
    *,
    profile: str,
    package_source: str,
    package_signature: str | None,
    publisher_id: str | None,
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type="tool.custom",
        tool_name="phaseB_tool",
        target="marketplace.skill.run",
        arguments={"task": "run skill"},
        input_class=InputClass.TRUSTED.value,
        prompt_provenance={
            "source": "user_request",
            "taint_level": "trusted",
            "source_chain": ["user_request", "tool_call"],
            "taint_markers": [],
        },
        package_source=package_source,
        package_hash="sha256:deadbeefcafebabe",
        package_signature=package_signature,
        publisher_id=publisher_id,
        policy_profile=profile,
    )


def test_prod_locked_blocks_unsigned_marketplace_package(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, profile="prod_locked")
    decision = rt.evaluate(
        _request(
            profile="prod_locked",
            package_source="clawhub",
            package_signature=None,
            publisher_id="official-publisher",
        )
    )

    assert decision.decision == "block"
    assert decision.reason_code == "UNSIGNED_MARKETPLACE_PACKAGE"
    assert decision.annotations["package_trust_guard"] is True
    assert decision.annotations["package_trust"]["signature_present"] is False

    witness = rt.last_witness
    assert witness is not None
    assert witness["package_trust"]["policy_reason"] == "UNSIGNED_MARKETPLACE_PACKAGE"
    assert witness["package_trust"]["policy_decision"] == "block"


def test_dev_strict_steps_up_unknown_marketplace_publisher(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, profile="dev_strict", trusted_publishers=["known-publisher"])
    decision = rt.evaluate(
        _request(
            profile="dev_strict",
            package_source="marketplace",
            package_signature="ed25519:abc123",
            publisher_id="unknown-publisher",
        )
    )

    assert decision.decision == "annotate"
    assert decision.reason_code == "UNKNOWN_PUBLISHER_STEP_UP"
    assert decision.annotations["enforcement_action"] == "block_until_approved"
    assert decision.annotations["package_trust"]["publisher_known"] is False

    witness = rt.last_witness
    assert witness is not None
    assert witness["package_trust"]["policy_reason"] == "UNKNOWN_PUBLISHER_STEP_UP"
    assert witness["package_trust"]["policy_decision"] == "annotate"


def test_dev_strict_allows_known_marketplace_publisher(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, profile="dev_strict", trusted_publishers=["known-publisher"])
    decision = rt.evaluate(
        _request(
            profile="dev_strict",
            package_source="clawhub_marketplace",
            package_signature="ed25519:signed",
            publisher_id="known-publisher",
        )
    )

    assert decision.decision == "allow"
    assert decision.reason_code == "POLICY_ALLOW"
    assert decision.annotations["package_trust"]["publisher_known"] is True
    assert decision.annotations["package_trust"]["signature_present"] is True


def test_prod_locked_steps_up_signed_unknown_publisher(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, profile="prod_locked", trusted_publishers=["known-publisher"])
    decision = rt.evaluate(
        _request(
            profile="prod_locked",
            package_source="clawhub",
            package_signature="ed25519:signed",
            publisher_id="unknown-publisher",
        )
    )

    assert decision.decision == "annotate"
    assert decision.reason_code == "UNKNOWN_PUBLISHER_STEP_UP"
    assert decision.annotations["enforcement_action"] == "block_until_approved"
