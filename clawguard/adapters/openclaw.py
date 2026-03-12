"""
OpenClaw Adapter for ClawGuard

Integrates ClawGuard enforcement into OpenClaw agent runtimes.

Usage:
    from clawguard.adapters import OpenClawAdapter

    adapter = OpenClawAdapter(profile="prod_locked")

    # Wrap OpenClaw tool
    protected_tool = adapter.wrap_tool(bash_tool)

    # Or intercept at event level
    adapter.intercept_tool_call(event)
"""

import uuid
from typing import Any, Callable, Optional

from clawguard.contracts import ActionRequest
from clawguard.exceptions import ExecutionBlocked
from clawguard.runtime import MVARRuntime


class OpenClawAdapter:
    """
    Adapter for integrating ClawGuard with OpenClaw agents.

    This adapter:
    1. Normalizes OpenClaw tool call events to ClawGuard ActionRequest
    2. Evaluates against policy via MVARRuntime
    3. Blocks execution if policy violation detected
    4. Allows execution if policy permits
    """

    def __init__(
        self,
        profile: str = "dev_balanced",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        Initialize OpenClaw adapter.

        Args:
            profile: Policy profile (dev_balanced, dev_strict, prod_locked)
            agent_id: Optional OpenClaw agent identifier
            session_id: Optional session identifier
        """
        self.runtime = MVARRuntime(profile=profile)
        self.profile = profile
        self.agent_id = agent_id or "openclaw_agent"
        self.session_id = session_id

    def wrap_tool(self, tool: Callable, sink_type: Optional[str] = None) -> Callable:
        """
        Wrap an OpenClaw tool with ClawGuard protection.

        Args:
            tool: The OpenClaw tool function to protect
            sink_type: The sink type (auto-detected if not provided)

        Returns:
            Protected tool function

        Example:
            bash_tool = adapter.wrap_tool(bash_execute, sink_type="shell.exec")
        """
        from functools import wraps

        # Auto-detect sink type from tool name if not provided
        if sink_type is None:
            sink_type = self._infer_sink_type(tool)

        tool_name = getattr(tool, "__name__", str(tool))

        @wraps(tool)
        def protected_tool(*args, **kwargs):
            # Extract target from arguments
            target = self._extract_target(tool_name, args, kwargs)

            # Build ActionRequest
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
                policy_profile=self.profile,
            )

            # Evaluate against policy
            decision = self.runtime.evaluate(request)

            # Block if policy violation
            if decision.is_blocked():
                raise ExecutionBlocked(decision)

            # Allow execution
            return tool(*args, **kwargs)

        # Mark as protected
        protected_tool.__clawguard_protected__ = True
        protected_tool.__clawguard_sink__ = sink_type

        return protected_tool

    def intercept_tool_call(self, event: dict) -> None:
        """
        Intercept an OpenClaw tool call event and evaluate against policy.

        Args:
            event: OpenClaw tool call event dictionary with keys:
                - tool_name: str
                - arguments: dict
                - context: dict (optional)

        Raises:
            ExecutionBlocked: If policy blocks the execution

        Example:
            event = {
                "tool_name": "bash_execute",
                "arguments": {"command": "rm -rf /"},
                "context": {"user_message": "clean up files"}
            }
            adapter.intercept_tool_call(event)  # Raises ExecutionBlocked
        """
        tool_name = event.get("tool_name", "unknown")
        arguments = event.get("arguments", {})
        context = event.get("context", {})

        # Infer sink type from tool name
        sink_type = self._infer_sink_type_from_name(tool_name)

        # Extract target
        target = self._extract_target_from_event(tool_name, arguments)

        # Build ActionRequest
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
            prompt_provenance=context,
            policy_profile=self.profile,
        )

        # Evaluate against policy
        decision = self.runtime.evaluate(request)

        # Block if policy violation
        if decision.is_blocked():
            raise ExecutionBlocked(decision)

        # Allow execution (caller proceeds)

    def _infer_sink_type(self, tool: Callable) -> str:
        """Infer sink type from tool function."""
        tool_name = getattr(tool, "__name__", "").lower()
        return self._infer_sink_type_from_name(tool_name)

    def _infer_sink_type_from_name(self, tool_name: str) -> str:
        """
        Infer sink type from tool name.

        Maps common OpenClaw tool patterns to sink types.
        """
        tool_name_lower = tool_name.lower()

        # Shell execution
        if any(x in tool_name_lower for x in ["bash", "shell", "exec", "command", "run"]):
            return "shell.exec"

        # Filesystem read
        if any(x in tool_name_lower for x in ["read", "cat", "view", "show", "get_file"]):
            return "filesystem.read"

        # Filesystem write
        if any(x in tool_name_lower for x in ["write", "save", "create", "delete", "remove", "mkdir"]):
            return "filesystem.write"

        # HTTP requests
        if any(x in tool_name_lower for x in ["http", "request", "fetch", "get", "post", "curl", "wget"]):
            return "http.request"

        # Credentials
        if any(x in tool_name_lower for x in ["env", "credential", "secret", "key", "token", "password"]):
            return "credentials.access"

        # Default
        return "tool.custom"

    def _extract_target(self, tool_name: str, args: tuple, kwargs: dict) -> Optional[str]:
        """Extract target from tool arguments."""
        # Try common argument names
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

        # Try first positional argument
        if args:
            return str(args[0])

        return None

    def _extract_target_from_event(self, tool_name: str, arguments: dict) -> Optional[str]:
        """Extract target from event arguments."""
        # Try common argument names
        for key in ["path", "file", "filename", "command", "url", "target"]:
            if key in arguments:
                return str(arguments[key])

        # Try first value if arguments is a dict
        if arguments:
            return str(next(iter(arguments.values())))

        return None


def create_openclaw_adapter(
    profile: str = "dev_balanced",
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> OpenClawAdapter:
    """
    Convenience function to create an OpenClaw adapter.

    Args:
        profile: Policy profile
        agent_id: Optional agent identifier
        session_id: Optional session identifier

    Returns:
        Configured OpenClawAdapter instance
    """
    return OpenClawAdapter(
        profile=profile,
        agent_id=agent_id,
        session_id=session_id,
    )
