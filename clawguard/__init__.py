"""
ClawGuard - Execution Firewall for AI Agents

ClawGuard wraps AI agent tools with MVAR runtime governance,
blocking attacker-influenced executions at critical sinks.

Example usage:
    from clawguard import protect

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

__version__ = "0.1.0"
__author__ = "MVAR Security"
__license__ = "Apache-2.0"

from clawguard.contracts import ActionDecision, ActionRequest
from clawguard.exceptions import (
    ClawGuardConfigError,
    ClawGuardError,
    ClawGuardRuntimeError,
    ExecutionBlocked,
    UnsupportedFrameworkError,
)
from clawguard.protect import protect
from clawguard.runtime import MVARRuntime
from clawguard.witness import (
    WitnessGenerator,
    generate_witness,
    get_witness_generator,
    set_witness_output_dir,
)

__all__ = [
    # Core API
    "protect",
    "MVARRuntime",
    # Contracts
    "ActionRequest",
    "ActionDecision",
    # Exceptions
    "ExecutionBlocked",
    "ClawGuardError",
    "ClawGuardConfigError",
    "ClawGuardRuntimeError",
    "UnsupportedFrameworkError",
    # Witness generation
    "WitnessGenerator",
    "generate_witness",
    "get_witness_generator",
    "set_witness_output_dir",
    # Adapters (optional import)
    "adapters",
]
