"""
ClawZero Adapters

Framework-specific adapters for integrating ClawZero with different AI agent systems.
"""

from clawzero.adapters.openclaw import OpenClawAdapter
from clawzero.adapters.langchain import (
    ClawZeroLangChainCallbackHandler,
    LangChainAdapter,
    protect_langchain_tool,
    wrap_langchain_tool,
)
from clawzero.adapters.crewai import CrewAIAdapter, protect_crewai_tool
from clawzero.adapters.autogen import AutoGenAdapter, protect_autogen_function
from clawzero.adapters.mcp import MCPAdapter, protect_mcp_call, infer_mcp_sink

__all__ = [
    "OpenClawAdapter",
    "LangChainAdapter",
    "ClawZeroLangChainCallbackHandler",
    "protect_langchain_tool",
    "wrap_langchain_tool",
    "CrewAIAdapter",
    "protect_crewai_tool",
    "AutoGenAdapter",
    "protect_autogen_function",
    "MCPAdapter",
    "protect_mcp_call",
    "infer_mcp_sink",
]
