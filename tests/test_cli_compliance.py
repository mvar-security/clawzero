"""CLI tests for `clawzero compliance verify` scaffolding."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli


def test_compliance_verify_writes_signed_attestation(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "tests").mkdir(parents=True, exist_ok=True)
    (repo_root / "tests" / "owasp").mkdir(parents=True, exist_ok=True)

    manifest = (
        {
            "name": "Suite A",
            "expected": 2,
            "paths": ("tests/alpha.py",),
        },
        {
            "name": "Suite B",
            "expected": 3,
            "paths": ("tests/owasp/beta.py",),
        },
    )
    for suite in manifest:
        for rel in suite["paths"]:
            path = repo_root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# present\n", encoding="utf-8")

    monkeypatch.setattr(cli, "COMPLIANCE_SUITE_MANIFEST", manifest)
    monkeypatch.setenv("CLAWZERO_STATE_DIR", str(tmp_path / ".clawzero"))

    output = tmp_path / "attestation.json"
    rc = cli.main(
        [
            "compliance",
            "verify",
            "--repo-root",
            str(repo_root),
            "--output",
            str(output),
        ]
    )
    out = capsys.readouterr().out

    assert rc == 0
    assert "Total expected scenarios: 5" in out
    assert output.exists()

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["all_suites_present"] is True
    assert payload["total_expected"] == 5
    assert str(payload["signature"]).startswith("ed25519")


def test_compliance_verify_fails_on_missing_suite_file(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir(parents=True, exist_ok=True)

    manifest = (
        {
            "name": "Missing Suite",
            "expected": 1,
            "paths": ("tests/missing.py",),
        },
    )
    monkeypatch.setattr(cli, "COMPLIANCE_SUITE_MANIFEST", manifest)
    monkeypatch.setenv("CLAWZERO_STATE_DIR", str(tmp_path / ".clawzero"))

    output = tmp_path / "attestation.json"
    rc = cli.main(
        [
            "compliance",
            "verify",
            "--repo-root",
            str(repo_root),
            "--output",
            str(output),
        ]
    )
    out = capsys.readouterr().out

    assert rc == 1
    assert "✗" in out
    assert output.exists()

