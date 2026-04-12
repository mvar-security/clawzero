"""CLI tests for keys/session/wrap commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
from clawzero.contracts import ActionDecision
from clawzero.runtime.session import AgentSession
from clawzero.witnesses.generator import WitnessGenerator


@pytest.fixture(autouse=True)
def _state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAWZERO_STATE_DIR", str(tmp_path / ".clawzero"))


def test_keys_show_missing_key(monkeypatch, capsys, tmp_path: Path) -> None:
    missing = tmp_path / "missing.pem"
    monkeypatch.setattr(cli, "_default_witness_key_path", lambda: missing)
    rc = cli.main(["keys", "show"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Status: missing" in out


def test_keys_show_prints_public_key(monkeypatch, capsys, tmp_path: Path) -> None:
    key_path = tmp_path / "keys" / "ed25519.pem"
    monkeypatch.setenv("CLAWZERO_WITNESS_KEY_PATH", str(key_path))
    generator = WitnessGenerator(output_dir=tmp_path / "witnesses")
    assert generator is not None

    rc = cli.main(["keys", "show"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Algorithm:   Ed25519" in out
    assert "Fingerprint:" in out


def test_session_start_creates_meta(capsys) -> None:
    session_id = f"s-{uuid.uuid4().hex[:8]}"
    rc = cli.main(["session", "start", "--session-id", session_id, "--profile", "dev_balanced"])
    out = capsys.readouterr().out
    assert rc == 0
    assert session_id in out
    state_root = Path(os.environ["CLAWZERO_STATE_DIR"])
    assert (state_root / "sessions" / f"{session_id}.meta.json").exists()


def test_session_status_missing_records(capsys) -> None:
    rc = cli.main(["session", "status", "missing-session-id"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "No session records found" in err


def test_session_status_reads_jsonl(capsys, tmp_path: Path) -> None:
    session = AgentSession(session_id=f"local-{uuid.uuid4().hex[:6]}", persistence_root=tmp_path)
    decision = ActionDecision(
        request_id=str(uuid.uuid4()),
        decision="block",
        reason_code="UNTRUSTED_TO_CRITICAL_SINK",
        human_reason="blocked",
        sink_type="shell.exec",
        target="bash",
        policy_profile="dev_balanced",
        trust_level="untrusted",
        annotations={"provenance": {"source": "doc", "taint_level": "untrusted"}},
    )
    session.evaluate(decision)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(cli, "_session_log_path", lambda _: session.log_path)
    monkeypatch.setattr(cli, "_session_meta_path", lambda _: tmp_path / "none.meta.json")
    try:
        rc = cli.main(["session", "status", session.session_id])
    finally:
        monkeypatch.undo()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Calls: 1" in out
    assert "Blocked: 1" in out


def test_wrap_block_path_does_not_execute_subprocess(monkeypatch, capsys, tmp_path: Path) -> None:
    called = {"ran": False}

    def _boom(*_args, **_kwargs):
        called["ran"] = True
        raise AssertionError("subprocess.run should not be called when blocked")

    monkeypatch.setattr(subprocess, "run", _boom)
    rc = cli.main(
        [
            "wrap",
            "--profile",
            "prod_locked",
            "--output-dir",
            str(tmp_path / "wrap"),
            "--",
            "python",
            "-c",
            "print('hello')",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "BLOCK" in out
    assert called["ran"] is False


def test_wrap_allow_path_executes_subprocess(monkeypatch, capsys, tmp_path: Path) -> None:
    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked", witness_dir: Path | None = None):
            self.profile = profile
            self.witness_dir = witness_dir
            self.last_witness = {"witness_id": "w-1"}

        def evaluate(self, request, session=None):  # noqa: ANN001
            decision = ActionDecision(
                request_id=request.request_id,
                decision="allow",
                reason_code="POLICY_ALLOW",
                human_reason="allowed",
                sink_type=request.sink_type,
                target=request.target,
                policy_profile=request.policy_profile,
                annotations=request.metadata.copy() if isinstance(request.metadata, dict) else {},
                trust_level="trusted",
            )
            if session is not None:
                decision = session.evaluate(decision)
            self.last_witness = {"witness_id": "w-1"}
            if session is not None:
                session.attach_witness(self.last_witness)
            return decision

    class _Proc:
        returncode = 0

    monkeypatch.setattr(cli, "MVARRuntime", FakeRuntime)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Proc())
    rc = cli.main(
        [
            "wrap",
            "--profile",
            "dev_balanced",
            "--input-class",
            "trusted",
            "--output-dir",
            str(tmp_path / "wrap"),
            "--",
            "python",
            "-c",
            "print('ok')",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Session complete" in out
    assert "Blocked: 0" in out


def test_session_report_json_output_file(capsys, tmp_path: Path) -> None:
    session_id = "report-json"
    log_path = tmp_path / f"{session_id}.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "request_id": "r1",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "sink_type": "shell.exec",
                "decision": "block",
                "reason_code": "UNTRUSTED_TO_CRITICAL_SINK",
                "taint_level": "untrusted",
                "source_id": "doc",
                "escalation_score": 3.0,
                "profile": "dev_balanced",
                "chain_patterns": ["taint_continuity"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(cli, "_session_log_path", lambda _: log_path)
    monkeypatch.setattr(cli, "_session_meta_path", lambda _: tmp_path / "missing.meta.json")
    output = tmp_path / "report.json"
    try:
        rc = cli.main(["session", "report", session_id, "--format", "json", "--output", str(output)])
    finally:
        monkeypatch.undo()
    out = capsys.readouterr().out
    assert rc == 0
    assert output.exists()
    assert "Session report written" in out


def test_session_report_sarif_requires_witness_dir(capsys, tmp_path: Path) -> None:
    session_id = "report-sarif"
    log_path = tmp_path / f"{session_id}.jsonl"
    log_path.write_text("{}", encoding="utf-8")
    meta_path = tmp_path / f"{session_id}.meta.json"
    meta_path.write_text(json.dumps({"session_id": session_id}), encoding="utf-8")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(cli, "_session_log_path", lambda _: log_path)
    monkeypatch.setattr(cli, "_session_meta_path", lambda _: meta_path)
    try:
        rc = cli.main(["session", "report", session_id, "--format", "sarif", "--output", str(tmp_path / "x.sarif")])
    finally:
        monkeypatch.undo()
    err = capsys.readouterr().err
    assert rc == 1
    assert "No witness_dir recorded" in err
