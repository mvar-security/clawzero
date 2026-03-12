"""
ClawGuard MVAR Runtime

Core enforcement engine powered by MVAR (MIRRA Verified Agent Runtime).
Evaluates action requests against policy and returns enforcement decisions.
"""

import uuid
from pathlib import Path
from typing import Optional

from clawguard.contracts import ActionDecision, ActionRequest
from clawguard.exceptions import ClawGuardConfigError
from clawguard.witness import generate_witness

# Try to import real MVAR runtime
try:
    from mvar.governor import ExecutionGovernor

    MVAR_AVAILABLE = True
except ImportError:
    MVAR_AVAILABLE = False


class MVARRuntime:
    """
    MVAR-powered enforcement runtime for AI agents.

    The runtime:
    1. Receives ActionRequest
    2. Evaluates against policy profile
    3. Returns ActionDecision (allow/block/annotate)
    4. Emits signed witness for audit trail

    V0.1: Policy evaluation logic embedded here.
    Future: Delegate to mvar-security>=1.4.0 for full IFC.
    """

    def __init__(
        self,
        profile: str = "dev_balanced",
        witness_dir: Optional[Path] = None,
    ):
        """
        Initialize MVAR runtime.

        Args:
            profile: Policy profile name (dev_balanced, dev_strict, prod_locked)
            witness_dir: Directory to write witness files (None = in-memory only)
        """
        self.profile = profile
        self.witness_dir = witness_dir
        self._load_policy(profile)

    def _load_policy(self, profile: str) -> None:
        """
        Load policy configuration for the given profile.

        V0.1: Hardcoded policies. Future: Load from profiles/*.yaml
        """
        # Hardcoded policies for v0.1
        if profile == "dev_balanced":
            self.policy = {
                "shell.exec": "block",
                "filesystem.read": {"mode": "allow", "block_paths": ["/etc/**", "~/.ssh/**"]},
                "filesystem.write": {"mode": "allow", "block_paths": ["/etc/**", "~/.ssh/**"]},
                "credentials.access": "block",
                "http.request": "allow",
                "tool.custom": "allow",
            }
        elif profile == "dev_strict":
            self.policy = {
                "shell.exec": "block",
                "filesystem.read": {"mode": "block", "allow_paths": ["/workspace/**"]},
                "filesystem.write": {"mode": "block", "allow_paths": ["/workspace/**"]},
                "credentials.access": "block",
                "http.request": {"mode": "allow", "block_domains": ["*"]},
                "tool.custom": "annotate",
            }
        elif profile == "prod_locked":
            self.policy = {
                "shell.exec": "block",
                "filesystem.read": {"mode": "block", "allow_paths": ["/workspace/project/**"]},
                "filesystem.write": {"mode": "block", "allow_paths": ["/workspace/project/**"]},
                "credentials.access": "block",
                "http.request": {"mode": "allow", "allow_domains": ["localhost"]},
                "tool.custom": "allow",
            }
        else:
            raise ClawGuardConfigError(f"Unknown policy profile: {profile}")

    def evaluate(self, request: ActionRequest) -> ActionDecision:
        """
        Evaluate an action request against policy.

        Args:
            request: The action being requested

        Returns:
            ActionDecision with allow/block/annotate and reason
        """
        sink_type = request.sink_type
        target = request.target or ""

        # Get policy rule for this sink
        policy_rule = self.policy.get(sink_type, "allow")

        # Simple policy evaluation (v0.1)
        if isinstance(policy_rule, str):
            # Simple mode: "allow", "block", "annotate"
            decision_result = policy_rule
            reason_code, human_reason = self._generate_reason(
                decision_result, sink_type, target
            )
        else:
            # Path/domain-based rules
            decision_result = self._evaluate_path_rule(
                policy_rule, sink_type, target
            )
            reason_code, human_reason = self._generate_reason(
                decision_result, sink_type, target, policy_rule
            )

        # Create decision
        decision = ActionDecision(
            request_id=request.request_id,
            decision=decision_result,
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=sink_type,
            policy_profile=self.profile,
            # V0.1: All inputs treated as untrusted
            # V1.0: Derive from request.prompt_provenance via MVAR taint analysis
            trust_level="untrusted",
            annotations={
                "taint_markers": ["external_input", "unverified_content"],
                "policy_rule_matched": sink_type,
            },
        )

        # Generate witness
        witness = generate_witness(request, decision)

        return decision

    def _evaluate_path_rule(
        self, rule: dict, sink_type: str, target: str
    ) -> str:
        """
        Evaluate path-based or domain-based policy rules.

        Args:
            rule: Policy rule dictionary with mode, allow_paths, block_paths, allow_domains, block_domains
            sink_type: Type of sink being accessed
            target: Target path/domain

        Returns:
            Decision: "allow", "block", or "annotate"
        """
        mode = rule.get("mode", "allow")

        # For HTTP requests, check domain rules
        if sink_type == "http.request":
            # Check block_domains first
            block_domains = rule.get("block_domains", [])
            for pattern in block_domains:
                if self._domain_matches(target, pattern):
                    return "block"

            # Check allow_domains
            allow_domains = rule.get("allow_domains", [])
            if allow_domains:
                for pattern in allow_domains:
                    if self._domain_matches(target, pattern):
                        return "allow"
                # No allowlist match → block
                return "block"
        else:
            # For filesystem, check path rules
            # Check block_paths first (takes precedence)
            block_paths = rule.get("block_paths", [])
            for pattern in block_paths:
                if self._path_matches(target, pattern):
                    return "block"

            # Check allow_paths
            allow_paths = rule.get("allow_paths", [])
            if allow_paths:
                for pattern in allow_paths:
                    if self._path_matches(target, pattern):
                        return "allow"
                # No allowlist match → block
                return "block"

        # Default to mode
        return mode

    def _path_matches(self, target: str, pattern: str) -> bool:
        """
        Check if target matches pattern.

        V0.1: Simple prefix matching. Future: Glob patterns.
        """
        # Expand ~
        if pattern.startswith("~"):
            pattern = pattern.replace("~", "/home/user")

        # Remove ** wildcard for simple prefix match
        pattern = pattern.replace("/**", "")

        return target.startswith(pattern)

    def _domain_matches(self, url: str, pattern: str) -> bool:
        """
        Check if URL matches domain pattern.

        Extracts hostname from URL (ignoring protocol, port, path) and
        matches against pattern.

        Args:
            url: Full URL (e.g., "http://localhost:8080/api")
            pattern: Domain pattern (e.g., "localhost", "*.example.com", "*")

        Returns:
            True if hostname matches pattern
        """
        from urllib.parse import urlparse

        # Extract hostname (without port)
        parsed = urlparse(url)
        hostname = parsed.hostname or url  # fallback to raw url if no scheme

        # Pattern matching
        if pattern == "*":
            return True

        if pattern.startswith("*."):
            # Wildcard subdomain: *.example.com matches sub.example.com
            return hostname.endswith(pattern[1:])

        # Exact hostname match
        return hostname == pattern

    def _generate_reason(
        self,
        decision: str,
        sink_type: str,
        target: str,
        rule: Optional[dict] = None,
    ) -> tuple[str, str]:
        """
        Generate reason_code and human_reason for a decision.

        Args:
            decision: The decision result
            sink_type: Type of sink
            target: Target of the action
            rule: Policy rule that matched (if any)

        Returns:
            (reason_code, human_reason)
        """
        if decision == "block":
            if rule and "block_paths" in rule:
                return (
                    "PATH_BLOCKED",
                    f"Target path '{target}' matches blocked path pattern in {self.profile} policy",
                )
            else:
                return (
                    "UNTRUSTED_TO_CRITICAL_SINK",
                    f"Untrusted input attempted to reach protected {sink_type} sink",
                )
        elif decision == "annotate":
            return (
                "POLICY_ANNOTATE",
                f"Action allowed with annotation: {sink_type} accessed",
            )
        else:  # allow
            if rule and "allow_paths" in rule:
                return (
                    "ALLOWLIST_MATCH",
                    f"Target path '{target}' matches allowed path pattern",
                )
            else:
                return (
                    "POLICY_ALLOW",
                    f"Action permitted by {self.profile} policy",
                )

    def emit_witness(self, decision: ActionDecision) -> None:
        """
        Emit witness for a decision (used for annotate mode).

        Args:
            decision: The decision to emit a witness for
        """
        # Witness already generated in evaluate(), this is a no-op
        # Kept for API compatibility
        pass
