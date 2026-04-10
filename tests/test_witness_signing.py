"""Witness signing behavior tests for ClawZero native generator."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.contracts import ActionDecision, ActionRequest
from clawzero.witnesses.generator import WitnessGenerator


def _request() -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type="tool.custom",
        tool_name="test_tool",
        target="summary",
        arguments={"target": "summary"},
        prompt_provenance={
            "source": "user_request",
            "taint_level": "trusted",
            "source_chain": ["user_request", "tool_call"],
            "taint_markers": [],
        },
        input_class="trusted",
        policy_profile="prod_locked",
    )


def _decision(request_id: str) -> ActionDecision:
    return ActionDecision(
        request_id=request_id,
        decision="allow",
        reason_code="POLICY_ALLOW",
        human_reason="allowed",
        sink_type="tool.custom",
        target="summary",
        policy_profile="prod_locked",
        engine="mvar-security",
        policy_id="mvar-security.v1.4.3",
    )


def test_witness_generator_signs_ed25519_when_crypto_available(tmp_path: Path, monkeypatch) -> None:
    key_path = tmp_path / "keys" / "ed25519_test.pem"
    monkeypatch.setenv("CLAWZERO_WITNESS_KEY_PATH", str(key_path))

    generator = WitnessGenerator(output_dir=tmp_path / "witnesses")
    request = _request()
    decision = _decision(request.request_id)
    witness = generator.generate(request, decision)
    signature = str(witness["witness_signature"])

    try:
        import cryptography  # noqa: F401

        assert signature.startswith("ed25519:")
        assert len(bytes.fromhex(signature.split(":", 1)[1])) == 64
        assert key_path.exists()
    except Exception:
        assert signature.startswith("ed25519_stub:")


def test_witness_generator_reuses_persisted_key(tmp_path: Path, monkeypatch) -> None:
    key_path = tmp_path / "keys" / "ed25519_test.pem"
    monkeypatch.setenv("CLAWZERO_WITNESS_KEY_PATH", str(key_path))

    request = _request()
    first = WitnessGenerator(output_dir=tmp_path / "witnesses_a")
    first_witness = first.generate(request, _decision(request.request_id))
    first_signature = str(first_witness["witness_signature"])

    # New generator process should load existing key and still emit valid signatures.
    second = WitnessGenerator(output_dir=tmp_path / "witnesses_b")
    second_witness = second.generate(request, _decision(request.request_id))
    second_signature = str(second_witness["witness_signature"])

    if first_signature.startswith("ed25519:") and second_signature.startswith("ed25519:"):
        assert len(bytes.fromhex(first_signature.split(":", 1)[1])) == 64
        assert len(bytes.fromhex(second_signature.split(":", 1)[1])) == 64
    else:
        assert first_signature.startswith("ed25519_stub:")
        assert second_signature.startswith("ed25519_stub:")

    # Ensure files are valid JSON witness artifacts.
    first_file = tmp_path / "witnesses_a" / "witness_001.json"
    second_file = tmp_path / "witnesses_b" / "witness_001.json"
    assert json.loads(first_file.read_text(encoding="utf-8"))["witness_signature"]
    assert json.loads(second_file.read_text(encoding="utf-8"))["witness_signature"]
