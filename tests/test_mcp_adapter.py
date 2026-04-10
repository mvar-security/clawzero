"""MCP adapter alpha tests."""

from __future__ import annotations

import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.adapters.mcp import MCPAdapter, infer_mcp_sink, protect_mcp_call
from clawzero.contracts import ActionDecision
from clawzero.exceptions import ExecutionBlocked


def test_infer_mcp_sink_from_tool_name() -> None:
    assert infer_mcp_sink("run_shell") == "shell.exec"
    assert infer_mcp_sink("fetch_url") == "http.request"
    assert infer_mcp_sink("read_secret") == "credentials.access"
    assert infer_mcp_sink("open_file") == "filesystem.read"


def test_protect_mcp_call_blocks_untrusted_critical(monkeypatch) -> None:
    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked"):
            _ = profile

        def evaluate(self, request):  # noqa: ANN001
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

    import clawzero.adapters.mcp as mcp_module

    monkeypatch.setattr(mcp_module, "MVARRuntime", FakeRuntime)

    def call_tool(tool_name: str, payload: dict):  # noqa: ANN001
        _ = tool_name, payload
        return {"ok": True}

    protected = protect_mcp_call(call_tool)

    try:
        protected("run_shell", {"command": "id"})
        assert False, "Expected ExecutionBlocked"
    except ExecutionBlocked as exc:
        assert exc.decision.reason_code == "UNTRUSTED_TO_CRITICAL_SINK"


def test_mcp_adapter_wrap_client_patches_method(monkeypatch) -> None:
    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked"):
            _ = profile

        def evaluate(self, request):  # noqa: ANN001
            return ActionDecision(
                request_id=request.request_id,
                decision="allow",
                reason_code="POLICY_ALLOW",
                human_reason="allowed",
                sink_type=request.sink_type,
                target=request.target,
                policy_profile="prod_locked",
                engine="mvar-security",
                policy_id="mvar-security.v1.4.3",
                witness_id=str(uuid.uuid4()),
            )

    import clawzero.adapters.mcp as mcp_module

    monkeypatch.setattr(mcp_module, "MVARRuntime", FakeRuntime)

    class Client:
        def call_tool(self, tool_name: str, payload: dict):  # noqa: ANN001
            return {"tool": tool_name, "payload": payload}

    client = Client()
    adapter = MCPAdapter(profile="prod_locked")
    wrapped_client = adapter.wrap_client(client)
    out = wrapped_client.call_tool("summarize", {"text": "hello"})
    assert out["tool"] == "summarize"
    assert getattr(wrapped_client, "__clawzero_protected__", False) is True
