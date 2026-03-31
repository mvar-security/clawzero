"""CrewAI adapter for ClawZero runtime enforcement.

Wraps CrewAI tools and agents with deterministic policy enforcement
at the tool-execution boundary.

Usage:
    from clawzero.adapters.crewai import protect_crewai_tool, CrewAIAdapter

    # Zero-config: wrap a single tool
    safe_tool = protect_crewai_tool(my_tool, sink="shell.exec")

    # Adapter pattern: wrap multiple tools
    adapter = CrewAIAdapter(profile="prod_locked")
    safe_tool = adapter.wrap_tool(my_tool, sink_type="shell.exec")
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from clawzero.contracts import ActionRequest, InputClass
from clawzero.exceptions import ExecutionBlocked
from clawzero.runtime import MVARRuntime


@dataclass
class _EnforcementContext:
    prompt_input: Any
    target: Optional[str]
    arguments: dict[str, Any]
    mode: str


class CrewAIAdapter:
    """Adapter for wrapping CrewAI tools with ClawZero enforcement.

    CrewAI tools typically inherit from ``crewai.tools.BaseTool`` or are plain
    callables decorated with ``@tool``.  This adapter handles both patterns.

    Example::

        from crewai import Agent, Task, Crew
        from crewai.tools import tool as crewai_tool
        from clawzero.adapters.crewai import CrewAIAdapter

        adapter = CrewAIAdapter(profile="prod_locked")

        @crewai_tool
        def run_command(command: str) -> str:
            '''Execute a shell command.'''
            import subprocess
            return subprocess.check_output(command, shell=True, text=True)

        safe_run = adapter.wrap_tool(run_command, sink_type="shell.exec")

        agent = Agent(
            role="DevOps Engineer",
            tools=[safe_run],
            ...
        )
    """

    ADAPTER_VERSION = "0.1.0"

    def __init__(
        self,
        profile: str = "dev_balanced",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        default_source: str = "external_document",
        default_taint_level: str = "untrusted",
    ):
        self.runtime = MVARRuntime(profile=profile)
        self.profile = profile
        self.agent_id = agent_id or "crewai_agent"
        self.session_id = session_id
        self.default_source = default_source
        self.default_taint_level = default_taint_level

    def wrap_tool(self, tool: Any, sink_type: Optional[str] = None) -> Any:
        """Wrap a CrewAI tool with deterministic sink enforcement.

        Args:
            tool: A CrewAI BaseTool instance or @tool-decorated callable.
            sink_type: Explicit sink classification. Auto-inferred if None.

        Returns:
            A protected wrapper that evaluates policy before every invocation.
        """
        if getattr(tool, "__clawzero_protected__", False):
            return tool

        if sink_type is None:
            sink_type = self._infer_sink_type(tool)

        tool_name = self._tool_name(tool)
        wrapped = _ProtectedCrewAITool(
            original=tool,
            adapter=self,
            sink_type=sink_type,
            tool_name=tool_name,
        )

        setattr(wrapped, "__clawzero_protected__", True)
        setattr(wrapped, "__clawzero_sink__", sink_type)
        setattr(wrapped, "__clawzero_framework__", "crewai")
        return wrapped

    def wrap_agent_tools(self, agent: Any) -> Any:
        """Wrap all tools on a CrewAI Agent object in place.

        Args:
            agent: A CrewAI Agent instance with a ``.tools`` list.

        Returns:
            The same agent with all tools wrapped.
        """
        tools = getattr(agent, "tools", None)
        if tools and isinstance(tools, list):
            agent.tools = [self.wrap_tool(t) for t in tools]
        return agent

    # ── Internal ─────────────────────────────────────────────────────

    def _evaluate_or_raise(self, tool_name: str, sink_type: str, context: _EnforcementContext) -> None:
        request = self._build_action_request(tool_name, sink_type, context)
        decision = self.runtime.evaluate(request)
        if decision.is_blocked():
            raise ExecutionBlocked(decision)

    def _build_action_request(
        self,
        tool_name: str,
        sink_type: str,
        context: _EnforcementContext,
    ) -> ActionRequest:
        provenance = self._build_prompt_provenance(context.prompt_input)
        return ActionRequest(
            request_id=str(uuid.uuid4()),
            framework="crewai",
            agent_id=self.agent_id,
            session_id=self.session_id,
            action_type="tool_call",
            sink_type=sink_type,
            tool_name=tool_name,
            target=context.target,
            arguments=context.arguments,
            input_class=self._input_class_from_provenance(provenance).value,
            prompt_provenance=provenance,
            policy_profile=self.profile,
            metadata={
                "adapter": {
                    "name": "crewai",
                    "mode": context.mode,
                    "framework": "crewai",
                }
            },
        )

    def _build_prompt_provenance(self, prompt_input: Any) -> dict[str, Any]:
        embedded: dict[str, Any] = {}
        if isinstance(prompt_input, dict):
            if isinstance(prompt_input.get("prompt_provenance"), dict):
                embedded = prompt_input["prompt_provenance"]
            elif isinstance(prompt_input.get("_clawzero_provenance"), dict):
                embedded = prompt_input["_clawzero_provenance"]

        source = str(embedded.get("source", self.default_source))
        taint_level = str(embedded.get("taint_level", self.default_taint_level))
        markers = embedded.get("taint_markers", [])
        source_chain = embedded.get("source_chain", [source, "crewai_tool_call"])

        if not isinstance(markers, list):
            markers = []
        if not isinstance(source_chain, list) or not source_chain:
            source_chain = [source, "crewai_tool_call"]

        return {
            "source": source,
            "taint_level": taint_level,
            "taint_markers": [str(m) for m in markers],
            "source_chain": [str(s) for s in source_chain],
            "adapter_version": self.ADAPTER_VERSION,
            "framework": "crewai",
        }

    @staticmethod
    def _input_class_from_provenance(provenance: dict[str, Any]) -> InputClass:
        value = str(provenance.get("input_class", "")).strip().lower()
        if value in {m.value for m in InputClass}:
            return InputClass(value)

        taint = str(provenance.get("taint_level", "")).strip().lower()
        if taint in {"trusted", "clean"}:
            return InputClass.TRUSTED
        if taint in {"pre_authorized", "pre-authorized"}:
            return InputClass.PRE_AUTHORIZED
        return InputClass.UNTRUSTED

    def _infer_sink_type(self, tool: Any) -> str:
        return self._infer_sink_type_from_name(self._tool_name(tool))

    @staticmethod
    def _tool_name(tool: Any) -> str:
        for attr in ("name", "__name__", "tool_name"):
            value = getattr(tool, attr, None)
            if isinstance(value, str):
                return value
        cls_name = getattr(type(tool), "__name__", None)
        if cls_name:
            return str(cls_name)
        return "crewai_tool"

    @staticmethod
    def _infer_sink_type_from_name(tool_name: str) -> str:
        name = tool_name.lower()
        if any(k in name for k in ("bash", "shell", "exec", "command", "run_command", "subprocess")):
            return "shell.exec"
        if any(k in name for k in ("read", "open", "load", "cat", "view", "file_read")):
            return "filesystem.read"
        if any(k in name for k in ("write", "save", "delete", "remove", "create", "mkdir", "file_write")):
            return "filesystem.write"
        if any(k in name for k in ("http", "request", "fetch", "url", "web", "curl", "api_call")):
            return "http.request"
        if any(k in name for k in ("credential", "secret", "token", "password", "env", "key", "ssh")):
            return "credentials.access"
        return "tool.custom"

    @staticmethod
    def _extract_target(
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        prompt_input: Any,
    ) -> Optional[str]:
        for key in ("path", "file", "filename", "command", "url", "target"):
            if key in kwargs:
                return str(kwargs[key])
        if isinstance(prompt_input, dict):
            for key in ("path", "file", "filename", "command", "url", "target"):
                if key in prompt_input:
                    return str(prompt_input[key])
        if args:
            return str(args[0])
        if isinstance(prompt_input, str):
            return prompt_input
        return tool_name


class _ProtectedCrewAITool:
    """Proxy that intercepts CrewAI tool execution patterns."""

    def __init__(self, original: Any, adapter: CrewAIAdapter, sink_type: str, tool_name: str):
        self._original = original
        self._adapter = adapter
        self._sink_type = sink_type
        self._tool_name = tool_name

    def __getattr__(self, item: str) -> Any:
        return getattr(self._original, item)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="tool_call")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if callable(self._original):
            return self._original(*args, **kwargs)
        raise AttributeError(f"Wrapped object '{self._tool_name}' is not callable")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """CrewAI BaseTool uses .run() as the primary entry point."""
        context = self._context(args, kwargs, mode="tool_run")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "run"):
            return self._original.run(*args, **kwargs)
        return self.__call__(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """CrewAI BaseTool uses ._run() internally."""
        context = self._context(args, kwargs, mode="tool_run_internal")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "_run"):
            return self._original._run(*args, **kwargs)
        return self.__call__(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """CrewAI async tool execution path."""
        context = self._context(args, kwargs, mode="tool_arun")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "_arun"):
            return await self._original._arun(*args, **kwargs)
        if hasattr(self._original, "_run"):
            return await asyncio.to_thread(self._original._run, *args, **kwargs)
        raise AttributeError(f"Wrapped object '{self._tool_name}' has no async entrypoint")

    def _context(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        mode: str,
    ) -> _EnforcementContext:
        prompt_input = kwargs.get("input", args[0] if args else kwargs)
        target = self._adapter._extract_target(
            tool_name=self._tool_name,
            args=args,
            kwargs=kwargs,
            prompt_input=prompt_input,
        )
        return _EnforcementContext(
            prompt_input=prompt_input,
            target=target,
            arguments={"args": args, "kwargs": kwargs},
            mode=mode,
        )


# ── Public convenience functions ─────────────────────────────────────

def protect_crewai_tool(
    tool: Any,
    sink: str = "tool.custom",
    profile: str = "dev_balanced",
    *,
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    source: str = "external_document",
    taint_level: str = "untrusted",
) -> Any:
    """Zero-config wrapper for CrewAI tools.

    Example::

        from clawzero.adapters.crewai import protect_crewai_tool

        safe_tool = protect_crewai_tool(my_tool, sink="shell.exec", profile="prod_locked")
    """
    adapter = CrewAIAdapter(
        profile=profile,
        agent_id=agent_id,
        session_id=session_id,
        default_source=source,
        default_taint_level=taint_level,
    )
    return adapter.wrap_tool(tool, sink_type=sink)
