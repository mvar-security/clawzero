"""Phase 4 CLI tests: explain, replay, attack-test, benchmark, claims file."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
from clawzero.contracts import ActionDecision, ActionRequest
from clawzero.runtime import MVARRuntime


def _runtime(tmp_path: Path, *, profile: str = "prod_locked") -> tuple[MVARRuntime, Path]:
    witness_dir = tmp_path / f"witnesses_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    runtime = MVARRuntime(profile=profile, witness_dir=witness_dir)
    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"
    return runtime, witness_dir


def _request(
    *,
    sink_type: str,
    target: str,
    source: str,
    taint_level: str,
    policy_profile: str = "prod_locked",
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="phase4_cli_tool",
        target=target,
        arguments={"target": target},
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "source_chain": [source, "tool_call"],
            "taint_markers": [] if taint_level == "trusted" else ["prompt_injection"],
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


def test_witness_explain_output(tmp_path: Path, capsys) -> None:
    runtime, witness_dir = _runtime(tmp_path)
    runtime.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
        )
    )
    witness_path = witness_dir / "witness_001.json"
    rc = cli.main(["witness", "explain", str(witness_path)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "ClawZero Execution Explanation" in out
    assert "Request" in out
    assert "Provenance" in out
    assert "Policy Evaluation" in out
    assert "Decision" in out
    assert "Witness" in out


def test_replay_orders_and_summarizes(tmp_path: Path, capsys) -> None:
    runtime, witness_dir = _runtime(tmp_path, profile="dev_balanced")
    runtime.evaluate(
        _request(
            sink_type="tool.custom",
            target="summary",
            source="user_request",
            taint_level="trusted",
            policy_profile="dev_balanced",
        )
    )
    runtime.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            policy_profile="prod_locked",
        )
    )

    rc = cli.main(["replay", "--session", str(witness_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SESSION REPLAY" in out
    assert "Step 1  [index 001]" in out
    assert "Step 2  [index 002]" in out
    assert "Session summary:" in out
    assert "Total: 2" in out


def test_attack_test_command_success(tmp_path: Path, capsys, monkeypatch) -> None:
    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked", witness_dir: Path | None = None, cec_enforce: bool = False):
            _ = profile, witness_dir, cec_enforce
            self.engine = "mvar-security"

        def evaluate(self, request: ActionRequest) -> ActionDecision:
            return ActionDecision(
                request_id=request.request_id,
                decision="block",
                reason_code="UNTRUSTED_TO_CRITICAL_SINK",
                human_reason="blocked",
                sink_type=request.sink_type,
                target=request.target,
                policy_profile="prod_locked",
                engine="mvar-security",
                policy_id="mvar-security.v1.4.5",
            )

    monkeypatch.setattr(cli, "MVARRuntime", FakeRuntime)
    output_dir = tmp_path / "attack_test_witnesses"
    rc = cli.main(["attack-test", "--output-dir", str(output_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ClawZero Attack Test Suite" in out
    assert "Results: 10/10 attacks blocked" in out
    assert "Engine:  mvar-security" in out


def test_benchmark_command_output_contract(tmp_path: Path, capsys, monkeypatch) -> None:
    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked", witness_dir: Path | None = None, cec_enforce: bool = False):
            _ = profile, witness_dir, cec_enforce
            self.engine = "mvar-security"

        def evaluate(self, request: ActionRequest) -> ActionDecision:
            decision = "block" if str(request.input_class) == "untrusted" else "allow"
            reason = "UNTRUSTED_TO_CRITICAL_SINK" if decision == "block" else "POLICY_ALLOW"
            return ActionDecision(
                request_id=request.request_id,
                decision=decision,
                reason_code=reason,
                human_reason=decision,
                sink_type=request.sink_type,
                target=request.target,
                policy_profile="prod_locked",
                engine="mvar-security",
                policy_id="mvar-security.v1.4.5",
            )

    monkeypatch.setattr(cli, "MVARRuntime", FakeRuntime)
    rc = cli.main(
        ["benchmark", "run", "--profile", "prod_locked", "--output-dir", str(tmp_path / "benchmark_witnesses")]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Attacks blocked: 35/35" in out
    assert "Benign allowed:  10/10" in out
    assert "Implemented corpus: 35 attacks, 10 benign" in out


def test_verified_claims_file_has_minimum_claims() -> None:
    root = Path(__file__).resolve().parents[1]
    claims_file = root / "VERIFIED_CLAIMS.md"
    assert claims_file.exists()
    text = claims_file.read_text(encoding="utf-8")
    assert text.count("## Claim:") >= 10

