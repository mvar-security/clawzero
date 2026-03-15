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

__all__ = [
    "OpenClawAdapter",
    "LangChainAdapter",
    "ClawZeroLangChainCallbackHandler",
    "protect_langchain_tool",
    "wrap_langchain_tool",
]
