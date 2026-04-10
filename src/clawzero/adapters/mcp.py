"""MCP adapter (alpha) for wrapping tool calls with ClawZero enforcement."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any

from clawzero.contracts import ActionRequest, InputClass
from clawzero.exceptions import ExecutionBlocked
from clawzero.runtime import MVARRuntime


def infer_mcp_sink(tool_name: str, schema: Any = None, default_sink: str = "tool.custom") -> str:
    """Infer sink type from MCP tool name and optional schema text."""
    name = tool_name.lower()
    schema_text = str(schema).lower() if schema is not None else ""
    haystack = f"{name} {schema_text}"

    if any(k in haystack for k in ("shell", "bash", "exec", "command", "subprocess")):
        return "shell.exec"
    if any(k in haystack for k in ("credential", "secret", "token", "password", "key", "env")):
        return "credentials.access"
    if any(k in haystack for k in ("file", "read", "write", "path", "fs")):
        return "filesystem.read"
    if any(k in haystack for k in ("http", "url", "request", "fetch", "webhook", "api")):
        return "http.request"
    return default_sink


class MCPAdapter:
    """Wrap MCP tool-call entrypoints with deterministic sink enforcement."""

    def __init__(
        self,
        profile: str = "prod_locked",
        *,
        framework: str = "mcp",
        input_class: InputClass = InputClass.UNTRUSTED,
        sink_map: dict[str, str] | None = None,
        default_sink: str = "tool.custom",
    ) -> None:
        self.profile = profile
        self.framework = framework
        self.input_class = input_class
        self.sink_map = sink_map or {}
        self.default_sink = default_sink
        self.runtime = MVARRuntime(profile=profile)

    def wrap_call(
        self,
        call_tool: Callable[..., Any] | Callable[..., Awaitable[Any]],
    ) -> Callable[..., Any]:
        """Wrap an MCP call_tool function (sync or async)."""
        if asyncio.iscoroutinefunction(call_tool):

            @wraps(call_tool)
            async def wrapped_async(tool_name: str, *args: Any, **kwargs: Any) -> Any:
                self._enforce(tool_name, args, kwargs)
                return await call_tool(tool_name, *args, **kwargs)

            return wrapped_async

        @wraps(call_tool)
        def wrapped_sync(tool_name: str, *args: Any, **kwargs: Any) -> Any:
            self._enforce(tool_name, args, kwargs)
            return call_tool(tool_name, *args, **kwargs)

        return wrapped_sync

    def wrap_client(self, client: Any, method_name: str = "call_tool") -> Any:
        """Patch a client-like object by wrapping its tool-call method."""
        method = getattr(client, method_name, None)
        if method is None or not callable(method):
            raise AttributeError(f"Client has no callable `{method_name}` method")

        wrapped = self.wrap_call(method)
        setattr(client, method_name, wrapped)
        setattr(client, "__clawzero_protected__", True)
        setattr(client, "__clawzero_framework__", self.framework)
        return client

    def _resolve_sink(self, tool_name: str, kwargs: dict[str, Any]) -> str:
        if tool_name in self.sink_map:
            return self.sink_map[tool_name]
        schema = kwargs.get("schema") or kwargs.get("input_schema")
        return infer_mcp_sink(tool_name, schema=schema, default_sink=self.default_sink)

    def _enforce(self, tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        sink = self._resolve_sink(tool_name, kwargs)
        trusted = self.input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
        request = ActionRequest(
            request_id=str(uuid.uuid4()),
            framework=self.framework,
            action_type="tool_call",
            sink_type=sink,
            tool_name=tool_name,
            target=tool_name,
            arguments={"args": args, "kwargs": kwargs},
            input_class=self.input_class.value,
            prompt_provenance={
                "source": "user_request" if trusted else "external_document",
                "taint_level": "trusted" if trusted else "untrusted",
                "source_chain": ["mcp_server", "tool_call"],
                "taint_markers": [] if trusted else ["external_content", "tool_request"],
            },
            policy_profile=self.profile,
            metadata={
                "adapter": {
                    "name": "mcp",
                    "mode": "tool_wrap",
                    "framework": self.framework,
                }
            },
        )
        decision = self.runtime.evaluate(request)
        if decision.is_blocked():
            raise ExecutionBlocked(decision)


def protect_mcp_call(
    call_tool: Callable[..., Any] | Callable[..., Awaitable[Any]],
    *,
    profile: str = "prod_locked",
    sink_map: dict[str, str] | None = None,
    default_sink: str = "tool.custom",
    input_class: InputClass = InputClass.UNTRUSTED,
) -> Callable[..., Any]:
    """Convenience wrapper for MCP tool call entrypoints."""
    adapter = MCPAdapter(
        profile=profile,
        sink_map=sink_map,
        default_sink=default_sink,
        input_class=input_class,
    )
    return adapter.wrap_call(call_tool)
