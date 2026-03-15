"""LangChain adapter for ClawZero runtime enforcement."""

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


class LangChainAdapter:
    """Adapter for wrapping LangChain tools and runnable chains."""

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
        self.agent_id = agent_id or "langchain_agent"
        self.session_id = session_id
        self.default_source = default_source
        self.default_taint_level = default_taint_level

    def wrap_tool(self, tool: Any, sink_type: Optional[str] = None) -> Any:
        """Wrap a LangChain tool/callable with deterministic sink enforcement."""
        if sink_type is None:
            sink_type = self._infer_sink_type(tool)

        tool_name = self._tool_name(tool)
        wrapped = _ProtectedLangChainObject(
            original=tool,
            adapter=self,
            sink_type=sink_type,
            tool_name=tool_name,
        )

        setattr(wrapped, "__clawzero_protected__", True)
        setattr(wrapped, "__clawzero_sink__", sink_type)
        setattr(wrapped, "__clawzero_framework__", "langchain")
        return wrapped

    def wrap_runnable(self, runnable: Any, sink_type: Optional[str] = None) -> Any:
        """Wrap a runnable chain (LCEL invoke/ainvoke) with the same policy path."""
        return self.wrap_tool(runnable, sink_type=sink_type or "tool.custom")

    def intercept_tool_call(self, event: dict[str, Any], mode: str = "callback_hook") -> None:
        """Intercept callback-style tool events from AgentExecutor hooks."""
        tool_name = str(event.get("tool_name", "unknown_tool"))
        arguments = event.get("arguments", {})
        sink_type = str(event.get("sink_type") or self._infer_sink_type_from_name(tool_name))
        target = self._extract_target(tool_name=tool_name, args=(), kwargs={}, prompt_input=arguments)
        request = self._build_action_request(
            tool_name=tool_name,
            sink_type=sink_type,
            context=_EnforcementContext(
                prompt_input=arguments,
                target=target,
                arguments=arguments if isinstance(arguments, dict) else {"input": arguments},
                mode=mode,
            ),
        )
        decision = self.runtime.evaluate(request)
        if decision.is_blocked():
            raise ExecutionBlocked(decision)

    def callback_handler(self, sink_overrides: Optional[dict[str, str]] = None) -> "ClawZeroLangChainCallbackHandler":
        """Return a callback handler compatible with LangChain callback managers."""
        return ClawZeroLangChainCallbackHandler(adapter=self, sink_overrides=sink_overrides or {})

    def _evaluate_or_raise(self, tool_name: str, sink_type: str, context: _EnforcementContext) -> None:
        request = self._build_action_request(
            tool_name=tool_name,
            sink_type=sink_type,
            context=context,
        )
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
            framework="langchain",
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
                    "name": "langchain",
                    "mode": context.mode,
                    "framework": "langchain",
                }
            },
        )

    def _build_prompt_provenance(self, prompt_input: Any) -> dict[str, Any]:
        embedded = {}
        if isinstance(prompt_input, dict):
            if isinstance(prompt_input.get("prompt_provenance"), dict):
                embedded = prompt_input["prompt_provenance"]
            elif isinstance(prompt_input.get("_clawzero_provenance"), dict):
                embedded = prompt_input["_clawzero_provenance"]
            else:
                embedded = prompt_input

        source = str(embedded.get("source", self.default_source))
        taint_level = str(embedded.get("taint_level", self.default_taint_level))
        markers = embedded.get("taint_markers", [])
        source_chain = embedded.get("source_chain", [source, "langchain_tool_call"])

        if not isinstance(markers, list):
            markers = []
        if not isinstance(source_chain, list) or not source_chain:
            source_chain = [source, "langchain_tool_call"]

        return {
            "source": source,
            "taint_level": taint_level,
            "taint_markers": [str(item) for item in markers],
            "source_chain": [str(item) for item in source_chain],
            "adapter_version": self.ADAPTER_VERSION,
            "framework": "langchain",
        }

    @staticmethod
    def _input_class_from_provenance(provenance: dict[str, Any]) -> InputClass:
        value = str(provenance.get("input_class", "")).strip().lower()
        if value in {member.value for member in InputClass}:
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
        for attr in ("name", "__name__", "__class__"):
            value = getattr(tool, attr, None)
            if value is None:
                continue
            if attr == "__class__":
                class_name = getattr(value, "__name__", None)
                if class_name:
                    return str(class_name)
            else:
                return str(value)
        return "langchain_tool"

    def _infer_sink_type_from_name(self, tool_name: str) -> str:
        name = tool_name.lower()
        if any(k in name for k in ("bash", "shell", "exec", "command", "run")):
            return "shell.exec"
        if any(k in name for k in ("read", "open", "load", "cat", "view", "show", "file")):
            return "filesystem.read"
        if any(k in name for k in ("write", "save", "delete", "remove", "create", "mkdir")):
            return "filesystem.write"
        if any(k in name for k in ("http", "request", "fetch", "url", "web", "curl")):
            return "http.request"
        if any(k in name for k in ("credential", "secret", "token", "password", "env")):
            return "credentials.access"
        return "tool.custom"

    def _extract_target(
        self,
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


class _ProtectedLangChainObject:
    def __init__(self, original: Any, adapter: LangChainAdapter, sink_type: str, tool_name: str):
        self._original = original
        self._adapter = adapter
        self._sink_type = sink_type
        self._tool_name = tool_name

    def __getattr__(self, item: str) -> Any:
        return getattr(self._original, item)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="tool_wrap")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if callable(self._original):
            return self._original(*args, **kwargs)
        if hasattr(self._original, "invoke"):
            return self._original.invoke(*args, **kwargs)
        raise AttributeError(f"Wrapped object '{self._tool_name}' is not callable")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="tool_run")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "run"):
            return self._original.run(*args, **kwargs)
        return self.__call__(*args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="lcel_invoke")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "invoke"):
            return self._original.invoke(*args, **kwargs)
        return self.__call__(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="tool_arun")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "arun"):
            return await self._original.arun(*args, **kwargs)
        if hasattr(self._original, "run"):
            return await asyncio.to_thread(self._original.run, *args, **kwargs)
        return await self.ainvoke(*args, **kwargs)

    async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:
        context = self._context(args, kwargs, mode="lcel_ainvoke")
        self._adapter._evaluate_or_raise(self._tool_name, self._sink_type, context)
        if hasattr(self._original, "ainvoke"):
            return await self._original.ainvoke(*args, **kwargs)
        if hasattr(self._original, "invoke"):
            return await asyncio.to_thread(self._original.invoke, *args, **kwargs)
        if callable(self._original):
            return await asyncio.to_thread(self._original, *args, **kwargs)
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
            arguments={
                "args": args,
                "kwargs": kwargs,
            },
            mode=mode,
        )


class ClawZeroLangChainCallbackHandler:
    """Callback-style interception for AgentExecutor tool-start events."""

    def __init__(self, adapter: LangChainAdapter, sink_overrides: dict[str, str]):
        self._adapter = adapter
        self._sink_overrides = sink_overrides

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = str(serialized.get("name", "unknown_tool"))
        sink_type = self._sink_overrides.get(tool_name)
        self._adapter.intercept_tool_call(
            {
                "tool_name": tool_name,
                "sink_type": sink_type,
                "arguments": {
                    "input": input_str,
                    "run_id": str(kwargs.get("run_id", "")),
                },
            },
            mode="callback_hook",
        )


def protect_langchain_tool(
    tool: Any,
    sink: str = "tool.custom",
    profile: str = "dev_balanced",
    *,
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    source: str = "external_document",
    taint_level: str = "untrusted",
) -> Any:
    """Zero-config wrapper for LangChain tools and runnables."""
    adapter = LangChainAdapter(
        profile=profile,
        agent_id=agent_id,
        session_id=session_id,
        default_source=source,
        default_taint_level=taint_level,
    )
    return adapter.wrap_tool(tool, sink_type=sink)


def wrap_langchain_tool(
    tool: Any,
    sink: str = "tool.custom",
    profile: str = "dev_balanced",
) -> Any:
    """Backward-compatible alias for protect_langchain_tool."""
    return protect_langchain_tool(tool=tool, sink=sink, profile=profile)
