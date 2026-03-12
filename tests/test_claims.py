"""Claim-level security tests for ClawZero + MVAR boundary behavior."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from pathlib import Path

import pytest

from clawzero import protect
from clawzero.adapters import OpenClawAdapter
from clawzero.contracts import ActionRequest
from clawzero.exceptions import ExecutionBlocked
from clawzero.runtime import MVARRuntime


def _request(
    *,
    sink_type: str,
    target: str,
    source: str,
    taint_level: str,
    taint_markers: list[str] | None = None,
    source_chain: list[str] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="sim_tool",
        target=target,
        arguments={"target": target},
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "taint_markers": taint_markers if taint_markers is not None else [],
            "source_chain": source_chain if source_chain is not None else [source, "tool_call"],
        },
        policy_profile="prod_locked",
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "event_intercept",
                "framework": "openclaw",
            }
        },
    )


def _runtime(tmp_path: Path, profile: str = "prod_locked") -> MVARRuntime:
    run_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return MVARRuntime(profile=profile, witness_dir=run_dir)


# Core attack vectors

def test_shell_injection_blocked(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="shell.exec",
        target="bash",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "block"


def test_credential_exfil_blocked(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="credentials.access",
        target="~/.ssh/id_rsa",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "block"


def test_http_exfil_blocked(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="http.request",
        target="https://attacker.example/collect",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "block"


def test_filesystem_protected_path_blocked(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="filesystem.read",
        target="/etc/passwd",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "block"


# Benign allows

def test_benign_request_allowed(tmp_path: Path):
    rt = _runtime(tmp_path, "dev_balanced")
    req = _request(
        sink_type="tool.custom",
        target="quarterly_report.md",
        source="user_request",
        taint_level="trusted",
        taint_markers=[],
        source_chain=["user_request", "tool_call"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "allow"


def test_localhost_allowed_prod_locked(tmp_path: Path):
    """Allowlist match overrides sink criticality. untrusted provenance does not universally block."""
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="http.request",
        target="http://localhost:8080/api",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
    )
    dec = rt.evaluate(req)
    assert dec.decision == "allow"


# Witness schema

def test_witness_schema_complete(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="shell.exec",
        target="bash",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection"],
    )
    rt.evaluate(req)
    witness = rt.last_witness
    assert witness is not None
    required = {
        "timestamp",
        "agent_runtime",
        "sink_type",
        "target",
        "decision",
        "reason_code",
        "policy_id",
        "provenance",
        "witness_signature",
        "engine",
        "adapter",
    }
    assert required.issubset(set(witness.keys()))


def test_witness_has_timestamp(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    rt.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            taint_markers=["prompt_injection"],
        )
    )
    assert isinstance(rt.last_witness["timestamp"], str)
    assert "T" in rt.last_witness["timestamp"]


def test_witness_has_policy_id(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    rt.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            taint_markers=["prompt_injection"],
        )
    )
    assert rt.last_witness["policy_id"]


def test_witness_has_engine_field(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    rt.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            taint_markers=["prompt_injection"],
        )
    )
    assert rt.last_witness["engine"] in {"embedded-policy-v0.1", "mvar-security"}


def test_witness_has_provenance_source(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    rt.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            taint_markers=["prompt_injection"],
        )
    )
    assert rt.last_witness["provenance"]["source"] == "external_document"


def test_witness_has_provenance_taint_level(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    rt.evaluate(
        _request(
            sink_type="tool.custom",
            target="quarterly_report.md",
            source="user_request",
            taint_level="trusted",
            taint_markers=[],
            source_chain=["user_request", "tool_call"],
        )
    )
    assert rt.last_witness["provenance"]["taint_level"] == "trusted"


# MVAR attribution

def test_mvar_attribution_present(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    dec = rt.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
            taint_markers=["prompt_injection"],
        )
    )
    assert dec.policy_id
    assert dec.engine
    assert "MVAR" in dec.human_reason


def test_zero_config_protect_api():
    def echo(value: str) -> str:
        return value

    safe = protect(echo)
    assert callable(safe)
    assert safe("ok") == "ok"


# OpenClaw adapter

def test_openclaw_wrap_tool_blocks():
    adapter = OpenClawAdapter(profile="prod_locked")

    def bash_execute(command: str) -> str:
        return command

    safe = adapter.wrap_tool(bash_execute, sink_type="shell.exec")
    with pytest.raises(ExecutionBlocked) as exc:
        safe("whoami")
    assert str(exc.value).startswith("MVAR blocked:")


def test_openclaw_wrap_tool_allows():
    adapter = OpenClawAdapter(profile="prod_locked")

    def http_get(url: str) -> str:
        return f"ok:{url}"

    safe = adapter.wrap_tool(http_get, sink_type="http.request")
    out = safe("http://localhost:8080/api")
    assert out.startswith("ok:")


def test_openclaw_event_intercept_blocks():
    adapter = OpenClawAdapter(profile="prod_locked")
    event = {
        "tool_name": "bash_execute",
        "arguments": {"command": "rm -rf /tmp/x"},
        "context": {"user_message": "clean files"},
    }
    with pytest.raises(ExecutionBlocked) as exc:
        adapter.intercept_tool_call(event)
    assert str(exc.value).startswith("MVAR blocked:")


def test_openclaw_event_intercept_allows():
    adapter = OpenClawAdapter(profile="prod_locked")
    event = {
        "tool_name": "http_get",
        "arguments": {"url": "http://localhost:8080/status"},
        "context": {"user_message": "status"},
    }
    adapter.intercept_tool_call(event)


# IFC vector tests

def test_indirect_prompt_injection_via_document(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="shell.exec",
        target="bash",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "external_content"],
        source_chain=["external_document", "llm_context", "tool_call"],
    )
    dec = rt.evaluate(req)
    witness = rt.last_witness
    assert dec.decision == "block"
    assert witness["provenance"]["source"] == "external_document"
    assert witness["provenance"]["taint_level"] == "untrusted"
    assert witness["provenance"]["taint_markers"]


def test_cross_context_taint_propagation(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="credentials.access",
        target="~/.ssh/id_rsa",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "cross_context"],
        source_chain=["external_document", "context_merge", "tool_call"],
    )
    dec = rt.evaluate(req)
    witness = rt.last_witness
    assert dec.decision == "block"
    assert witness["provenance"]["source"] == "external_document"
    assert witness["provenance"]["taint_level"] == "untrusted"
    assert witness["provenance"]["taint_markers"]


def test_credential_exfil_via_summarization_task(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="credentials.access",
        target="/home/user/.ssh/id_rsa",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "summarization_hijack"],
        source_chain=["external_document", "summary_prompt", "tool_call"],
    )
    dec = rt.evaluate(req)
    witness = rt.last_witness
    assert dec.decision == "block"
    assert witness["provenance"]["source"] == "external_document"
    assert witness["provenance"]["taint_level"] == "untrusted"
    assert witness["provenance"]["taint_markers"]


def test_shell_injection_via_benign_tool_chain(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="shell.exec",
        target="bash",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "tool_chain"],
        source_chain=["external_document", "benign_tool", "tool_call"],
    )
    dec = rt.evaluate(req)
    witness = rt.last_witness
    assert dec.decision == "block"
    assert witness["provenance"]["source"] == "external_document"
    assert witness["provenance"]["taint_level"] == "untrusted"
    assert witness["provenance"]["taint_markers"]


def test_multi_hop_taint_reaches_critical_sink(tmp_path: Path):
    rt = _runtime(tmp_path, "prod_locked")
    req = _request(
        sink_type="shell.exec",
        target="bash",
        source="external_document",
        taint_level="untrusted",
        taint_markers=["prompt_injection", "multi_hop"],
        source_chain=[
            "external_document",
            "doc_parser",
            "llm_context",
            "tool_selection",
            "tool_call",
        ],
    )
    dec = rt.evaluate(req)
    witness = rt.last_witness
    assert dec.decision == "block"
    assert witness["provenance"]["source"] == "external_document"
    assert witness["provenance"]["taint_level"] == "untrusted"
    assert witness["provenance"]["taint_markers"]
