"""Doctor CLI tests for OpenClaw runtime/witness/demo checks."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
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
