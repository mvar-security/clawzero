"""
ClawZero - Execution Firewall for AI Agents

ClawZero wraps AI agent tools with MVAR runtime governance,
blocking attacker-influenced executions at critical sinks.

Example usage:
    from clawzero import protect

    def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    safe_read = protect(read_file, sink="filesystem.read", profile="prod_locked")

    # Blocked: /etc/passwd is in blocklist
    try:
        safe_read("/etc/passwd")
    except ExecutionBlocked as e:
        print(f"Blocked: {e.decision.human_reason}")

    # Allowed: /workspace is in allowlist
    content = safe_read("/workspace/data.txt")
"""

__version__ = "0.1.1"
__author__ = "MVAR Security"
__license__ = "Apache-2.0"

from clawzero.contracts import ActionDecision, ActionRequest, InputClass
from clawzero.adapters import (
    OpenClawAdapter,
    LangChainAdapter,
    protect_langchain_tool,
    wrap_langchain_tool,
)
from clawzero.exceptions import (
    ClawZeroConfigError,
    ClawZeroError,
    ClawZeroRuntimeError,
    ExecutionBlocked,
    UnsupportedFrameworkError,
)
from clawzero.protect import protect
from clawzero.runtime import MVARRuntime
from clawzero.witness import (
    WitnessGenerator,
    generate_witness,
    get_witness_generator,
    set_witness_output_dir,
)

__all__ = [
    # Core API
    "protect",
    "MVARRuntime",
    "OpenClawAdapter",
    "LangChainAdapter",
    "protect_langchain_tool",
    "wrap_langchain_tool",
    # Contracts
    "ActionRequest",
    "ActionDecision",
    "InputClass",
    # Exceptions
    "ExecutionBlocked",
    "ClawZeroError",
    "ClawZeroConfigError",
    "ClawZeroRuntimeError",
    "UnsupportedFrameworkError",
    # Witness generation
    "WitnessGenerator",
    "generate_witness",
    "get_witness_generator",
    "set_witness_output_dir",
    # Adapters (optional import)
    "adapters",
]
