"""AutoGen adapter for ClawZero runtime enforcement.

Wraps AutoGen functions and tool registrations with deterministic policy
enforcement at the tool-execution boundary.

Usage:
    from clawzero.adapters.autogen import protect_autogen_function, AutoGenAdapter

    # Zero-config: wrap a single function
    safe_func = protect_autogen_function(my_func, sink="shell.exec")

    # Adapter pattern: wrap and register
    adapter = AutoGenAdapter(profile="prod_locked")
    safe_func = adapter.wrap_function(my_func, sink_type="shell.exec")

    # Patch an agent's function map
    adapter.protect_agent(autogen_agent)
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from clawzero.contracts import ActionRequest, InputClass
from clawzero.exceptions import ExecutionBlocked
from clawzero.runtime import MVARRuntime


@dataclass
class _EnforcementContext:
    prompt_input: Any
    target: Optional[str]
    arguments: dict[str, Any]
    mode: str


class AutoGenAdapter:
    """Adapter for wrapping AutoGen functions with ClawZero enforcement.

    AutoGen agents use a ``function_map`` dict or ``register_function()``
    to expose tools.  This adapter wraps individual functions or patches
    the function map in-place.

    Example::

        import autogen
        from clawzero.adapters.autogen import AutoGenAdapter

        adapter = AutoGenAdapter(profile="prod_locked")

        def execute_code(code: str) -> str:
            ...

        safe_execute = adapter.wrap_function(
            execute_code, sink_type="shell.exec"
        )

        assistant = autogen.AssistantAgent(
            name="coder",
            function_map={"execute_code": safe_execute},
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
        self.agent_id = agent_id or "autogen_agent"
        self.session_id = session_id
        self.default_source = default_source
        self.default_taint_level = default_taint_level

    def wrap_function(
        self,
        func: Callable,
        sink_type: Optional[str] = None,
        func_name: Optional[str] = None,
    ) -> Callable:
        """Wrap an AutoGen function with deterministic sink enforcement.

        Args:
            func: The function to protect.
            sink_type: Explicit sink classification. Auto-inferred if None.
            func_name: Override for the function name used in policy evaluation.

        Returns:
            A protected wrapper that evaluates policy before every invocation.
        """
        if getattr(func, "__clawzero_protected__", False):
            return func

        tool_name = str(func_name or getattr(func, "__name__", str(func)))
        if sink_type is None:
            sink_type = self._infer_sink_type_from_name(tool_name)

        def protected(*args: Any, **kwargs: Any) -> Any:
            context = self._build_context(tool_name, args, kwargs, mode="function_call")
            request = self._build_action_request(tool_name, sink_type, context)
            decision = self.runtime.evaluate(request)
            if decision.is_blocked():
                raise ExecutionBlocked(decision)
            return func(*args, **kwargs)

        async def async_protected(*args: Any, **kwargs: Any) -> Any:
            context = self._build_context(tool_name, args, kwargs, mode="async_function_call")
            request = self._build_action_request(tool_name, sink_type, context)
            decision = self.runtime.evaluate(request)
            if decision.is_blocked():
                raise ExecutionBlocked(decision)
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return await asyncio.to_thread(func, *args, **kwargs)

        wrapper = async_protected if asyncio.iscoroutinefunction(func) else protected

        # Preserve metadata
        wrapper.__name__ = tool_name
        wrapper.__doc__ = func.__doc__
        setattr(wrapper, "__clawzero_protected__", True)
        setattr(wrapper, "__clawzero_sink__", sink_type)
        setattr(wrapper, "__clawzero_framework__", "autogen")
        setattr(wrapper, "__wrapped__", func)

        return wrapper

    def protect_agent(
        self,
        agent: Any,
        sink_map: Optional[dict[str, str]] = None,
        default_sink: str = "tool.custom",
    ) -> Any:
        """Wrap all functions in an AutoGen agent's function_map.

        Args:
            agent: An AutoGen agent with a ``function_map`` attribute.
            sink_map: Optional mapping of function names to sink types.
            default_sink: Sink type for functions not in sink_map.

        Returns:
            The same agent with all functions wrapped.
        """
        sink_map = sink_map or {}
        func_map = getattr(agent, "function_map", None) or getattr(agent, "_function_map", None)

        if func_map and isinstance(func_map, dict):
            protected_map = {}
            for name, func in func_map.items():
                sink = sink_map.get(name, self._infer_sink_type_from_name(name))
                if sink == "tool.custom" and default_sink != "tool.custom":
                    sink = default_sink
                protected_map[name] = self.wrap_function(func, sink_type=sink, func_name=name)

            # Try to set back on the agent
            for attr in ("function_map", "_function_map"):
                try:
                    setattr(agent, attr, protected_map)
                    break
                except AttributeError:
                    continue

        return agent

    # ── Internal ─────────────────────────────────────────────────────

    def _build_context(
        self,
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        mode: str,
    ) -> _EnforcementContext:
        prompt_input = kwargs if kwargs else (args[0] if args else {})
        target = self._extract_target(tool_name, args, kwargs, prompt_input)
        return _EnforcementContext(
            prompt_input=prompt_input,
            target=target,
            arguments={"args": args, "kwargs": kwargs},
            mode=mode,
        )

    def _build_action_request(
        self,
        tool_name: str,
        sink_type: str,
        context: _EnforcementContext,
    ) -> ActionRequest:
        provenance = self._build_prompt_provenance(context.prompt_input)
        return ActionRequest(
            request_id=str(uuid.uuid4()),
            framework="autogen",
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
                    "name": "autogen",
                    "mode": context.mode,
                    "framework": "autogen",
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
        source_chain = embedded.get("source_chain", [source, "autogen_function_call"])

        if not isinstance(markers, list):
            markers = []
        if not isinstance(source_chain, list) or not source_chain:
            source_chain = [source, "autogen_function_call"]

        return {
            "source": source,
            "taint_level": taint_level,
            "taint_markers": [str(m) for m in markers],
            "source_chain": [str(s) for s in source_chain],
            "adapter_version": self.ADAPTER_VERSION,
            "framework": "autogen",
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

    @staticmethod
    def _infer_sink_type_from_name(tool_name: str) -> str:
        name = tool_name.lower()
        if any(k in name for k in ("bash", "shell", "exec", "command", "run_command", "subprocess", "code")):
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
        for key in ("path", "file", "filename", "command", "url", "target", "code"):
            if key in kwargs:
                return str(kwargs[key])
        if isinstance(prompt_input, dict):
            for key in ("path", "file", "filename", "command", "url", "target", "code"):
                if key in prompt_input:
                    return str(prompt_input[key])
        if args:
            return str(args[0])
        if isinstance(prompt_input, str):
            return prompt_input
        return tool_name


# ── Public convenience functions ─────────────────────────────────────

def protect_autogen_function(
    func: Callable,
    sink: str = "tool.custom",
    profile: str = "dev_balanced",
    *,
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    source: str = "external_document",
    taint_level: str = "untrusted",
) -> Callable:
    """Zero-config wrapper for AutoGen functions.

    Example::

        from clawzero.adapters.autogen import protect_autogen_function

        safe_func = protect_autogen_function(my_func, sink="shell.exec", profile="prod_locked")
    """
    adapter = AutoGenAdapter(
        profile=profile,
        agent_id=agent_id,
        session_id=session_id,
        default_source=source,
        default_taint_level=taint_level,
    )
    return adapter.wrap_function(func, sink_type=sink)
