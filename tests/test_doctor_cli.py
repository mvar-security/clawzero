"""Doctor CLI tests for OpenClaw runtime/witness/demo checks."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
from clawzero.contracts import ActionDecision, ActionRequest
from clawzero.doctor import DoctorCheck, DoctorReport


def _report(runtime: DoctorCheck, witness: DoctorCheck, demo: DoctorCheck) -> DoctorReport:
    return DoctorReport(runtime=runtime, witness=witness, demo=demo)


def test_doctor_secure_path(monkeypatch, capsys) -> None:
    report = _report(
        DoctorCheck("Runtime", "OK", "mvar-security 1.4.3"),
        DoctorCheck("Witness", "OK", "chain valid"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    rc = cli.main(["doctor", "openclaw"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Runtime......... OK (mvar-security 1.4.3)" in out
    assert "Witness......... OK (chain valid)" in out
    assert "Demo............ OK (attack blocked)" in out
    assert "Status: SECURE" in out


def test_doctor_warn_no_mvar(monkeypatch, capsys) -> None:
    report = _report(
        DoctorCheck("Runtime", "WARN", "embedded fallback"),
        DoctorCheck("Witness", "OK", "chain valid"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    rc = cli.main(["doctor", "openclaw"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "Runtime......... WARN (embedded fallback)" in out
    assert "Witness......... OK (chain valid)" in out
    assert "Demo............ OK (attack blocked)" in out
    assert "Status: WARNINGS (see above)" in out


def test_doctor_chain_invalid(monkeypatch, capsys) -> None:
    report = _report(
        DoctorCheck("Runtime", "OK", "mvar-security 1.4.3"),
        DoctorCheck("Witness", "INVALID", "previous_hash mismatch at index 2"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    rc = cli.main(["doctor", "openclaw"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "Witness......... INVALID (previous_hash mismatch at index 2)" in out
    assert "Status: WARNINGS (see above)" in out


def test_doctor_exposure_line_rendered(monkeypatch, capsys) -> None:
    report = _report(
        DoctorCheck("Runtime", "OK", "mvar-security 1.4.3"),
        DoctorCheck("Witness", "OK", "chain valid"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    report.exposure = DoctorCheck("Exposure", "OK", "control-plane guards active")
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    rc = cli.main(["doctor", "openclaw"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Exposure........ OK (control-plane guards active)" in out


def test_prove_command_secure(monkeypatch, capsys, tmp_path) -> None:
    report = _report(
        DoctorCheck("Runtime", "OK", "mvar-security 1.4.3"),
        DoctorCheck("Witness", "OK", "chain valid"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    report.exposure = DoctorCheck("Exposure", "OK", "control-plane guards active")
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked", witness_dir=None, cec_enforce: bool = False):
            _ = profile, cec_enforce
            self._witness_dir = witness_dir

        def evaluate(self, request: ActionRequest) -> ActionDecision:
            witness_path = self._witness_dir / "witness_001.json"
            witness_path.write_text(json.dumps({"witness_signature": "ed25519:test"}), encoding="utf-8")
            return ActionDecision(
                request_id=request.request_id,
                decision="block",
                reason_code="UNTRUSTED_TO_CRITICAL_SINK",
                human_reason="blocked",
                sink_type=request.sink_type,
                target=request.target,
                policy_profile="prod_locked",
                engine="mvar-security",
                policy_id="mvar-security.v1.4.3",
            )

        def signer_info(self) -> dict[str, str | None]:
            return {
                "witness_signer": "Ed25519 (QSEAL) ✓",
                "ledger_signer": "HMAC fallback",
                "ledger_signer_detail": "(external signer not configured)",
            }

    monkeypatch.setattr(cli, "MVARRuntime", FakeRuntime)

    rc = cli.main(["prove", "--output-dir", str(tmp_path / "prove_witnesses")])
    out = capsys.readouterr().out

    assert rc == 0
    assert "[1/3] Runtime check......." in out
    assert "[2/3] Attack simulation... BLOCKED ✓ (shell.exec)" in out
    assert "[3/3] Witness generated... YES (Ed25519 (QSEAL) ✓)" in out
    assert "Status: SECURE" in out


def test_prove_command_require_mvar_fails_when_runtime_warn(monkeypatch, capsys, tmp_path) -> None:
    report = _report(
        DoctorCheck("Runtime", "WARN", "mvar-security missing"),
        DoctorCheck("Witness", "OK", "chain valid"),
        DoctorCheck("Demo", "OK", "attack blocked"),
    )
    monkeypatch.setattr(cli, "run_openclaw_doctor", lambda: report)

    rc = cli.main(
        [
            "prove",
            "--require-mvar",
            "--output-dir",
            str(tmp_path / "prove_witnesses"),
        ]
    )
    out = capsys.readouterr().out

    assert rc == 1
    assert "[1/3] Runtime check....... WARN (mvar-security missing)" in out
    assert "requires mvar-security" in out
