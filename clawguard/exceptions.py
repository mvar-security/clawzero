"""
ClawGuard Exceptions

All enforcement-related exceptions that ClawGuard can raise.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clawguard.contracts import ActionDecision


class ClawGuardError(Exception):
    """Base exception for all ClawGuard errors"""

    pass


class ExecutionBlocked(ClawGuardError):
    """
    Raised when ClawGuard blocks an action from executing.

    This exception carries the full ActionDecision that explains
    why the execution was blocked. The decision includes:
    - reason_code: machine-readable classification
    - human_reason: explanation for logs/users
    - witness_id: reference to the signed witness
    """

    def __init__(self, decision: "ActionDecision"):
        self.decision = decision
        super().__init__(decision.human_reason)

    def __str__(self) -> str:
        return (
            f"ClawGuard blocked execution\n"
            f"  Reason: {self.decision.human_reason}\n"
            f"  Code: {self.decision.reason_code}\n"
            f"  Sink: {self.decision.sink_type}\n"
            f"  Policy: {self.decision.policy_profile}\n"
            f"  Witness: {self.decision.witness_id or 'N/A'}"
        )


class ClawGuardConfigError(ClawGuardError):
    """
    Raised when ClawGuard configuration is invalid or missing.

    Examples:
    - Invalid policy profile name
    - Missing required policy file
    - Malformed YAML in policy definition
    """

    pass


class ClawGuardRuntimeError(ClawGuardError):
    """
    Raised when ClawGuard encounters an unexpected runtime error.

    This should be rare - most enforcement failures result in
    ExecutionBlocked, not exceptions.
    """

    pass


class UnsupportedFrameworkError(ClawGuardError):
    """
    Raised when attempting to protect a tool from an unsupported framework.

    ClawGuard requires a framework adapter to integrate with agent runtimes.
    If no adapter exists, this exception is raised.
    """

    pass
