"""ClawZero exceptions."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from clawzero.contracts import ActionDecision


class ClawZeroError(Exception):
    """Base exception for all ClawZero errors."""


class ExecutionBlocked(ClawZeroError):
    """Raised when MVAR blocks an action from reaching a protected sink."""

    def __init__(self, decision: "ActionDecision"):
        self.decision = decision
        message = f"MVAR blocked: {decision.reason_code} — {decision.human_reason}"
        super().__init__(message)

    def __str__(self) -> str:
        return f"MVAR blocked: {self.decision.reason_code} — {self.decision.human_reason}"


class ClawZeroConfigError(ClawZeroError):
    """Raised when ClawZero configuration is invalid or missing."""


class ClawZeroRuntimeError(ClawZeroError):
    """Raised when ClawZero encounters an unexpected runtime error."""


class UnsupportedFrameworkError(ClawZeroError):
    """Raised when attempting to protect a tool from an unsupported framework."""
