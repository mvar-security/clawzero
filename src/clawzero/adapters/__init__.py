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
]
