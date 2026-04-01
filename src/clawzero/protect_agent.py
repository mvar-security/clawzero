"""
ClawZero protect_agent() — zero-config agent-level protection.

Wraps all tools on an agent object with ClawZero enforcement in one call.

Usage:
    from clawzero import protect_agent

    safe_agent = protect_agent(my_agent, profile="prod_locked")
    safe_agent.run("do the task")
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from clawzero.protect import protect

logger = logging.getLogger(__name__)

# Common tool attribute names across agent frameworks
_TOOL_ATTRS = ("tools", "_tools", "tool_list", "registered_tools", "functions")
_TOOL_NAME_ATTRS = ("name", "__name__", "tool_name", "function_name")


def protect_agent(
    agent: Any,
    profile: str = "prod_locked",
    *,
    sink_map: Optional[dict[str, str]] = None,
    default_sink: str = "tool.custom",
    framework: str = "auto",
) -> Any:
    """
    Wrap all tools on an agent with ClawZero enforcement.

    Automatically detects tools on the agent object and wraps each one
    with deterministic policy enforcement. Works with OpenClaw, LangChain,
    CrewAI, AutoGen, and any agent that exposes tools as a list or dict.

    Args:
        agent: The agent object whose tools should be protected.
        profile: Policy profile (dev_balanced, dev_strict, prod_locked).
        sink_map: Optional mapping of tool names to sink types.
                  e.g. {"bash_execute": "shell.exec", "read_file": "filesystem.read"}
        default_sink: Sink type for tools not in sink_map.
        framework: Framework hint. "auto" detects from agent type.

    Returns:
        The same agent with all tools wrapped by ClawZero enforcement.

    Example:
        ```python
        from clawzero import protect_agent

        # Protect every tool on the agent
        safe_agent = protect_agent(agent, profile="prod_locked")

        # With explicit sink mapping
        safe_agent = protect_agent(agent, sink_map={
            "execute_command": "shell.exec",
            "read_file": "filesystem.read",
            "fetch_url": "http.request",
        })
        ```
    """
    sink_map = sink_map or {}
    detected_framework = _detect_framework(agent) if framework == "auto" else framework

    tools_wrapped = 0

    # Strategy 1: Agent has a .tools list (OpenClaw, LangChain AgentExecutor, CrewAI)
    for attr in _TOOL_ATTRS:
        tools = getattr(agent, attr, None)
        if tools is None:
            continue

        if isinstance(tools, list):
            wrapped = []
            for tool in tools:
                wrapped_tool = _wrap_single_tool(
                    tool, profile, sink_map, default_sink, detected_framework
                )
                wrapped.append(wrapped_tool)
                tools_wrapped += 1
            try:
                setattr(agent, attr, wrapped)
            except AttributeError:
                logger.warning("Cannot set %s on agent (read-only attribute)", attr)
            break

        if isinstance(tools, dict):
            wrapped_dict = {}
            for name, tool in tools.items():
                sink = sink_map.get(name, _infer_sink(name, default_sink))
                wrapped_dict[name] = protect(
                    tool, sink=sink, profile=profile, framework=detected_framework
                )
                tools_wrapped += 1
            try:
                setattr(agent, attr, wrapped_dict)
            except AttributeError:
                logger.warning("Cannot set %s on agent (read-only attribute)", attr)
            break

    # Strategy 2: Agent uses register_tool / add_tool pattern
    if tools_wrapped == 0:
        for method_name in ("register_tool", "add_tool", "register_function"):
            original_method = getattr(agent, method_name, None)
            if original_method and callable(original_method):
                _patch_registration_method(
                    agent, method_name, original_method,
                    profile, sink_map, default_sink, detected_framework
                )
                tools_wrapped = -1  # Patched for future registrations
                break

    if tools_wrapped == 0:
        logger.warning(
            "protect_agent: No tools found on agent (%s). "
            "If your agent registers tools later, call protect_agent() after registration.",
            type(agent).__name__,
        )

    logger.info(
        "ClawZero: protected %s tools on %s (profile=%s, framework=%s)",
        tools_wrapped if tools_wrapped > 0 else "registration_patched",
        type(agent).__name__,
        profile,
        detected_framework,
    )

    return agent


def _detect_framework(agent: Any) -> str:
    """Detect the agent framework from the agent object type."""
    type_name = type(agent).__name__.lower()
    module = getattr(type(agent), "__module__", "") or ""

    if "openclaw" in module or "openclaw" in type_name:
        return "openclaw"
    if "langchain" in module or "langchain" in type_name:
        return "langchain"
    if "crewai" in module or "crew" in type_name:
        return "crewai"
    if "autogen" in module or "autogen" in type_name:
        return "autogen"

    return "python_tools"


def _wrap_single_tool(
    tool: Any,
    profile: str,
    sink_map: dict[str, str],
    default_sink: str,
    framework: str,
) -> Any:
    """Wrap a single tool object with ClawZero protection."""
    # Don't double-wrap
    if getattr(tool, "__clawzero_protected__", False):
        return tool

    tool_name = _get_tool_name(tool)
    sink = sink_map.get(tool_name, _infer_sink(tool_name, default_sink))

    if callable(tool):
        return protect(tool, sink=sink, profile=profile, framework=framework)

    # Tool object with .run() or .invoke() — wrap those methods
    for method_name in ("run", "invoke", "__call__"):
        method = getattr(tool, method_name, None)
        if method and callable(method):
            protected = protect(method, sink=sink, profile=profile, framework=framework)
            try:
                setattr(tool, method_name, protected)
            except AttributeError:
                pass

    setattr(tool, "__clawzero_protected__", True)
    return tool


def _get_tool_name(tool: Any) -> str:
    """Extract name from a tool object."""
    for attr in _TOOL_NAME_ATTRS:
        val = getattr(tool, attr, None)
        if isinstance(val, str):
            return val
    return type(tool).__name__


def _infer_sink(tool_name: str, default: str) -> str:
    """Infer sink type from tool name heuristics."""
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
    return default


def _patch_registration_method(
    agent: Any,
    method_name: str,
    original_method: Callable,
    profile: str,
    sink_map: dict[str, str],
    default_sink: str,
    framework: str,
) -> None:
    """Patch a tool registration method to auto-wrap new tools."""
    def patched_register(tool: Any, *args: Any, **kwargs: Any) -> Any:
        wrapped = _wrap_single_tool(tool, profile, sink_map, default_sink, framework)
        return original_method(wrapped, *args, **kwargs)

    setattr(agent, method_name, patched_register)
