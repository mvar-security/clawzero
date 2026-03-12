"""
OpenClaw adapter for ClawZero.

Integrates OpenClaw tool activity with MVAR enforcement.
"""

import uuid
from typing import Callable, Optional

from clawzero.contracts import ActionRequest
from clawzero.exceptions import ExecutionBlocked
from clawzero.runtime import MVARRuntime


class OpenClawAdapter:
    """Adapter for integrating ClawZero with OpenClaw runtimes."""

    ADAPTER_VERSION = "0.1.0"

    def __init__(
        self,
        profile: str = "dev_balanced",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.runtime = MVARRuntime(profile=profile)
        self.profile = profile
        self.agent_id = agent_id or "openclaw_agent"
        self.session_id = session_id

    def wrap_tool(self, tool: Callable, sink_type: Optional[str] = None) -> Callable:
        """Wrap an OpenClaw tool with MVAR enforcement."""
        from functools import wraps

        if sink_type is None:
            sink_type = self._infer_sink_type(tool)

        tool_name = getattr(tool, "__name__", str(tool))

        @wraps(tool)
        def protected_tool(*args, **kwargs):
            target = self._extract_target(tool_name, args, kwargs)

            request = ActionRequest(
                request_id=str(uuid.uuid4()),
                framework="openclaw",
                agent_id=self.agent_id,
                session_id=self.session_id,
                action_type="tool_call",
                sink_type=sink_type,
                tool_name=tool_name,
                target=target,
                arguments={"args": args, "kwargs": kwargs},
                prompt_provenance=self._build_prompt_provenance(),
                policy_profile=self.profile,
                metadata={
                    "adapter": self._build_adapter_metadata(mode="tool_wrap"),
                },
            )

            decision = self.runtime.evaluate(request)

            if decision.is_blocked():
                raise ExecutionBlocked(decision)

            return tool(*args, **kwargs)

        protected_tool.__clawzero_protected__ = True
        protected_tool.__clawzero_sink__ = sink_type

        return protected_tool

    def intercept_tool_call(self, event: dict) -> None:
        """Intercept and enforce an OpenClaw tool-call event."""
        tool_name = event.get("tool_name", "unknown")
        arguments = event.get("arguments", {})

        sink_type = self._infer_sink_type_from_name(tool_name)
        target = self._extract_target_from_event(tool_name, arguments)

        request = ActionRequest(
            request_id=str(uuid.uuid4()),
            framework="openclaw",
            agent_id=self.agent_id,
            session_id=self.session_id,
            action_type="tool_call",
            sink_type=sink_type,
            tool_name=tool_name,
            target=target,
            arguments=arguments,
            prompt_provenance=self._build_prompt_provenance(),
            policy_profile=self.profile,
            metadata={
                "adapter": self._build_adapter_metadata(mode="event_intercept"),
            },
        )

        decision = self.runtime.evaluate(request)

        if decision.is_blocked():
            raise ExecutionBlocked(decision)

    def _build_prompt_provenance(self) -> dict:
        """Return canonical OpenClaw provenance for all adapter request paths."""
        return {
            "source": "openclaw_tool_call",
            "adapter_version": self.ADAPTER_VERSION,
            "framework": "openclaw",
            "taint_level": "untrusted",
        }

    def _build_adapter_metadata(self, mode: str) -> dict:
        """Return canonical adapter metadata for witness emission."""
        return {
            "name": "openclaw",
            "mode": mode,
            "framework": "openclaw",
        }

    def _infer_sink_type(self, tool: Callable) -> str:
        tool_name = getattr(tool, "__name__", "").lower()
        return self._infer_sink_type_from_name(tool_name)

    def _infer_sink_type_from_name(self, tool_name: str) -> str:
        tool_name_lower = tool_name.lower()

        if any(x in tool_name_lower for x in ["bash", "shell", "exec", "command", "run"]):
            return "shell.exec"

        if any(x in tool_name_lower for x in ["read", "open", "load", "cat", "view", "show", "get_file"]):
            return "filesystem.read"

        if any(x in tool_name_lower for x in ["write", "save", "create", "delete", "remove", "mkdir"]):
            return "filesystem.write"

        if any(x in tool_name_lower for x in ["http", "request", "fetch", "get", "post", "curl", "wget"]):
            return "http.request"

        if any(x in tool_name_lower for x in ["env", "cred", "credential", "secret", "key", "token", "password"]):
            return "credentials.access"

        return "tool.custom"

    def _extract_target(self, tool_name: str, args: tuple, kwargs: dict) -> Optional[str]:
        if "path" in kwargs:
            return str(kwargs["path"])
        if "file" in kwargs:
            return str(kwargs["file"])
        if "filename" in kwargs:
            return str(kwargs["filename"])
        if "command" in kwargs:
            return str(kwargs["command"])
        if "url" in kwargs:
            return str(kwargs["url"])

        if args:
            return str(args[0])

        return None

    def _extract_target_from_event(self, tool_name: str, arguments: dict) -> Optional[str]:
        for key in ["path", "file", "filename", "command", "url", "target"]:
            if key in arguments:
                return str(arguments[key])

        if arguments:
            return str(next(iter(arguments.values())))

        return None


def create_openclaw_adapter(
    profile: str = "dev_balanced",
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> OpenClawAdapter:
    """Convenience constructor for OpenClawAdapter."""
    return OpenClawAdapter(
        profile=profile,
        agent_id=agent_id,
        session_id=session_id,
    )
