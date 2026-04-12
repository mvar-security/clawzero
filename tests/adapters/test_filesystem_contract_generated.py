"""Filesystem contract suite for framework adapters.

Focus:
  - Untrusted traversal-like read intents are blocked.
  - Trusted workspace read intents are permitted where supported.
  - Witness artifacts carry filesystem sink metadata.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    ),
)

from clawzero.adapters import AutoGenAdapter, CrewAIAdapter, LangChainAdapter, MCPAdapter, OpenClawAdapter
from clawzero.contracts import InputClass
from clawzero.exceptions import ExecutionBlocked

SAFE_PATHS: tuple[str, ...] = (
    "/workspace/project/report_01.md",
    "/workspace/project/report_02.md",
    "/workspace/project/report_03.md",
    "/workspace/project/report_04.md",
    "/workspace/project/report_05.md",
    "/workspace/project/report_06.md",
)

TRAVERSAL_PATHS: tuple[str, ...] = (
    "/workspace/../../etc/passwd",
    "/workspace/../../../etc/shadow",
    "/tmp/../etc/hosts",
    "/workspace/project/../../../private/var/db",
    "/workspace/%2e%2e/%2e%2e/etc/passwd",
    "../../etc/passwd",
)

BLOCK_REASON_CODES = {
    "PATH_BLOCKED",
    "UNTRUSTED_TO_CRITICAL_SINK",
    "POLICY_BLOCK",
    "STEP_UP_REQUIRED",
}


@dataclass(frozen=True)
class FilesystemCase:
    adapter: str
    path: str
    trusted: bool

    @property
    def case_id(self) -> str:
        mode = "trusted" if self.trusted else "untrusted"
        path_kind = "safe" if self.trusted else "traversal"
        return f"{self.adapter}__{mode}__{path_kind}__{abs(hash(self.path)) % 10000:04d}"


def _cases() -> list[FilesystemCase]:
    rows: list[FilesystemCase] = []
    for adapter in ("openclaw", "langchain", "crewai", "autogen", "mcp"):
        rows.extend(FilesystemCase(adapter=adapter, path=path, trusted=True) for path in SAFE_PATHS)
        rows.extend(FilesystemCase(adapter=adapter, path=path, trusted=False) for path in TRAVERSAL_PATHS)
    return rows


def _run_openclaw(case: FilesystemCase) -> tuple[OpenClawAdapter, object]:
    adapter = OpenClawAdapter(profile="dev_balanced")

    def tool(path: str) -> str:
        return f"read:{path}"

    wrapped = adapter.wrap_tool(tool, sink_type="filesystem.read")
    result = wrapped(case.path)
    return adapter, result


def _run_langchain(case: FilesystemCase) -> tuple[LangChainAdapter, object]:
    adapter = LangChainAdapter(profile="dev_balanced")

    def tool(payload):  # noqa: ANN001
        return payload

    wrapped = adapter.wrap_tool(tool, sink_type="filesystem.read")
    payload = {
        "path": case.path,
        "prompt_provenance": {
            "source": "user_request" if case.trusted else "external_document",
            "taint_level": "trusted" if case.trusted else "untrusted",
            "source_chain": ["filesystem_contract", "adapter", "langchain"],
            "taint_markers": [] if case.trusted else ["external_content"],
        },
    }
    result = wrapped(payload)
    return adapter, result


def _run_crewai(case: FilesystemCase) -> tuple[CrewAIAdapter, object]:
    adapter = CrewAIAdapter(profile="dev_balanced")

    def tool(payload):  # noqa: ANN001
        return payload

    wrapped = adapter.wrap_tool(tool, sink_type="filesystem.read")
    payload = {
        "path": case.path,
        "prompt_provenance": {
            "source": "user_request" if case.trusted else "external_document",
            "taint_level": "trusted" if case.trusted else "untrusted",
            "source_chain": ["filesystem_contract", "adapter", "crewai"],
            "taint_markers": [] if case.trusted else ["external_content"],
        },
    }
    result = wrapped(payload)
    return adapter, result


def _run_autogen(case: FilesystemCase) -> tuple[AutoGenAdapter, object]:
    adapter = AutoGenAdapter(profile="dev_balanced")

    def tool(payload):  # noqa: ANN001
        return payload

    wrapped = adapter.wrap_function(tool, sink_type="filesystem.read", func_name="read_file")
    payload = {
        "path": case.path,
        "prompt_provenance": {
            "source": "user_request" if case.trusted else "external_document",
            "taint_level": "trusted" if case.trusted else "untrusted",
            "source_chain": ["filesystem_contract", "adapter", "autogen"],
            "taint_markers": [] if case.trusted else ["external_content"],
        },
    }
    result = wrapped(payload)
    return adapter, result


def _run_mcp(case: FilesystemCase) -> tuple[MCPAdapter, object]:
    adapter = MCPAdapter(
        profile="dev_balanced",
        sink_map={"read_file": "filesystem.read"},
        input_class=InputClass.TRUSTED if case.trusted else InputClass.UNTRUSTED,
    )

    def call_tool(tool_name: str, payload: dict):  # noqa: ANN001
        return {"tool": tool_name, "payload": payload}

    wrapped = adapter.wrap_call(call_tool)
    result = wrapped("read_file", {"path": case.path})
    return adapter, result


def _execute(case: FilesystemCase):
    if case.adapter == "openclaw":
        return _run_openclaw(case)
    if case.adapter == "langchain":
        return _run_langchain(case)
    if case.adapter == "crewai":
        return _run_crewai(case)
    if case.adapter == "autogen":
        return _run_autogen(case)
    return _run_mcp(case)


@pytest.mark.parametrize("case", [pytest.param(case, id=case.case_id) for case in _cases()])
def test_adapter_filesystem_contract_generated(case: FilesystemCase) -> None:
    should_block = not case.trusted

    if should_block:
        with pytest.raises(ExecutionBlocked) as exc:
            _execute(case)
        assert exc.value.decision.reason_code in BLOCK_REASON_CODES
        return

    if case.adapter == "openclaw":
        # OpenClaw adapter currently emits untrusted provenance by design,
        # so trusted/allow behavior is policy-dependent across engines.
        try:
            adapter, result = _execute(case)
            assert result is not None
            witness = adapter.runtime.last_witness
            assert isinstance(witness, dict)
            assert witness.get("sink_type") == "filesystem.read"
            provenance = witness.get("provenance")
            assert isinstance(provenance, dict)
            assert str(provenance.get("taint_level")) == "untrusted"
            return
        except ExecutionBlocked as exc:
            assert exc.value.decision.reason_code in BLOCK_REASON_CODES
            return

    adapter, result = _execute(case)
    assert result is not None
    witness = adapter.runtime.last_witness
    assert isinstance(witness, dict)
    assert witness.get("sink_type") == "filesystem.read"
    assert witness.get("decision") in {"allow", "annotate"}
    provenance = witness.get("provenance")
    assert isinstance(provenance, dict)
    assert str(provenance.get("taint_level")) == "trusted"
