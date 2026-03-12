"""
ClawGuard protect() wrapper

Zero-config protection for AI agent tools.

Usage:
    from clawguard import protect

    safe_tool = protect(my_tool, sink="filesystem.read")
    result = safe_tool(path="/workspace/file.txt")
"""

import inspect
import uuid
from functools import wraps
from typing import Any, Callable, Optional

from clawguard.contracts import ActionRequest
from clawguard.exceptions import ExecutionBlocked
from clawguard.runtime import MVARRuntime


# Global runtime instance
_global_runtime: Optional[MVARRuntime] = None


def get_runtime(profile: str = "dev_balanced") -> MVARRuntime:
    """Get or create the global runtime instance"""
    global _global_runtime
    if _global_runtime is None or _global_runtime.profile != profile:
        _global_runtime = MVARRuntime(profile=profile)
    return _global_runtime


def protect(
    tool: Callable,
    sink: str = "tool.custom",
    profile: str = "dev_balanced",
    framework: str = "python_tools",
) -> Callable:
    """
    Wrap a tool with ClawGuard enforcement.

    This is the zero-config entry point for ClawGuard protection.

    Args:
        tool: The tool function to protect
        sink: Sink type classification (e.g., "filesystem.read", "shell.exec")
        profile: Policy profile to apply (dev_balanced, dev_strict, prod_locked)
        framework: Framework identifier for logging

    Returns:
        Protected version of the tool that enforces policy before execution

    Example:
        ```python
        from clawguard import protect

        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()

        safe_read_file = protect(read_file, sink="filesystem.read", profile="prod_locked")

        # This will be blocked:
        try:
            safe_read_file(path="/etc/passwd")
        except ExecutionBlocked as e:
            print(f"Blocked: {e.decision.human_reason}")

        # This will be allowed (if /workspace is in allowlist):
        content = safe_read_file(path="/workspace/data.txt")
        ```
    """
    runtime = get_runtime(profile)
    tool_name = tool.__name__ if hasattr(tool, "__name__") else str(tool)

    @wraps(tool)
    def protected_tool(*args, **kwargs):
        # Extract target from arguments
        target = _extract_target(tool, args, kwargs)

        # Build action request
        request = ActionRequest(
            request_id=str(uuid.uuid4()),
            framework=framework,
            action_type="tool_call",
            sink_type=sink,
            tool_name=tool_name,
            target=target,
            arguments={"args": args, "kwargs": kwargs},
            policy_profile=profile,
        )

        # Evaluate
        decision = runtime.evaluate(request)

        # Enforce
        if decision.is_blocked():
            raise ExecutionBlocked(decision)

        if decision.is_annotated():
            # Annotate but allow
            runtime.emit_witness(decision)

        # Execute original tool
        return tool(*args, **kwargs)

    # Preserve metadata
    protected_tool.__clawguard_protected__ = True
    protected_tool.__clawguard_sink__ = sink
    protected_tool.__clawguard_profile__ = profile

    return protected_tool


def _extract_target(tool: Callable, args: tuple, kwargs: dict) -> Optional[str]:
    """
    Extract target from tool arguments.

    Heuristic: Look for common parameter names like 'path', 'url', 'command', 'target'.

    Args:
        tool: The tool function
        args: Positional arguments
        kwargs: Keyword arguments

    Returns:
        Extracted target string, or None
    """
    # Check kwargs first
    target_param_names = ["path", "target", "url", "command", "file", "filename"]
    for param_name in target_param_names:
        if param_name in kwargs:
            return str(kwargs[param_name])

    # Check args by inspecting function signature
    try:
        sig = inspect.signature(tool)
        param_names = list(sig.parameters.keys())

        for i, arg in enumerate(args):
            if i < len(param_names):
                param_name = param_names[i]
                if param_name in target_param_names:
                    return str(arg)
    except Exception:
        pass

    # Default: use first argument if available
    if args:
        return str(args[0])

    return None
