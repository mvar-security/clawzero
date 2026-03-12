"""
ClawGuard Core Contracts

Data contracts for action requests and enforcement decisions.
Every enforcement decision is auditable, traceable, and witness-signed.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ActionRequest:
    """
    Represents a request to execute an action in an AI agent.

    Every tool call, API request, or privileged operation flows through
    an ActionRequest before execution. ClawGuard evaluates the request
    against policy and returns an ActionDecision.
    """

    request_id: str
    """Unique identifier for this action request"""

    framework: str
    """Framework originating the request (e.g., 'openclaw', 'langchain', 'mcp')"""

    agent_id: Optional[str] = None
    """Agent instance identifier"""

    session_id: Optional[str] = None
    """Session or conversation identifier"""

    action_type: str = "tool_call"
    """Type of action: tool_call, api_request, shell_exec, file_operation"""

    sink_type: str = "tool.custom"
    """Sink classification: shell.exec, filesystem.read, http.request, etc."""

    tool_name: Optional[str] = None
    """Name of the tool being invoked"""

    target: Optional[str] = None
    """Target of the action (file path, URL, command, etc.)"""

    arguments: dict[str, Any] = field(default_factory=dict)
    """Arguments passed to the action"""

    prompt_provenance: dict[str, Any] = field(default_factory=dict)
    """Provenance tracking: which parts came from user vs system vs tool output"""

    conversation_context: dict[str, Any] = field(default_factory=dict)
    """Recent conversation context for policy evaluation"""

    policy_profile: str = "dev_balanced"
    """Policy profile to apply: dev_balanced, dev_strict, prod_locked"""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional metadata for logging, debugging, or custom policies"""


@dataclass
class ActionDecision:
    """
    ClawGuard's enforcement decision for an ActionRequest.

    Every decision is deterministic, auditable, and emits a signed witness.
    Decisions are one of: allow, block, annotate.
    """

    request_id: str
    """Matches the ActionRequest.request_id this decision applies to"""

    decision: str
    """Enforcement decision: 'allow' | 'block' | 'annotate'"""

    reason_code: str
    """
    Machine-readable reason code:
    - UNTRUSTED_TO_CRITICAL_SINK
    - POLICY_VIOLATION
    - ALLOWLIST_MATCH
    - DEFAULT_DENY
    - etc.
    """

    human_reason: str
    """Human-readable explanation of the decision"""

    sink_type: str
    """Sink type this decision applies to"""

    policy_profile: str
    """Policy profile used to make this decision"""

    trust_level: Optional[str] = None
    """Trust level of the input: trusted, untrusted, derived"""

    witness_id: Optional[str] = None
    """UUID of the signed witness for this decision"""

    annotations: dict[str, Any] = field(default_factory=dict)
    """
    Additional annotations:
    - provenance_chain: list of transformation steps
    - taint_markers: list of taint tags applied
    - policy_rule_matched: which rule triggered the decision
    - severity: low, medium, high, critical
    """

    def is_blocked(self) -> bool:
        """Returns True if this decision blocks execution"""
        return self.decision == "block"

    def is_allowed(self) -> bool:
        """Returns True if this decision allows execution"""
        return self.decision == "allow"

    def is_annotated(self) -> bool:
        """Returns True if this decision annotates but allows execution"""
        return self.decision == "annotate"
