"""
ClawZero contracts.

Data contracts for execution-boundary requests and decisions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class InputClass(str, Enum):
    """Request integrity class for policy strictness."""

    TRUSTED = "trusted"
    PRE_AUTHORIZED = "pre_authorized"
    UNTRUSTED = "untrusted"


@dataclass
class ActionRequest:
    """A request entering the execution boundary."""

    request_id: str
    framework: str

    agent_id: Optional[str] = None
    session_id: Optional[str] = None

    action_type: str = "tool_call"
    sink_type: str = "tool.custom"

    tool_name: Optional[str] = None
    target: Optional[str] = None

    arguments: dict[str, Any] = field(default_factory=dict)
    prompt_provenance: dict[str, Any] = field(default_factory=dict)
    conversation_context: dict[str, Any] = field(default_factory=dict)
    input_class: Optional[str] = None

    policy_profile: str = "dev_balanced"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionDecision:
    """Deterministic policy decision emitted by the runtime."""

    request_id: str
    decision: str
    reason_code: str
    human_reason: str

    sink_type: str
    target: Optional[str]
    policy_profile: str

    engine: str = "embedded-policy-v0.1"
    policy_id: str = "mvar-embedded.v0.1"

    trust_level: Optional[str] = None
    witness_id: Optional[str] = None

    annotations: dict[str, Any] = field(default_factory=dict)

    def is_blocked(self) -> bool:
        return self.decision == "block"

    def is_allowed(self) -> bool:
        return self.decision == "allow"

    def is_annotated(self) -> bool:
        return self.decision == "annotate"
