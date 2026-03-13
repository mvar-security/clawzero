"""
ClawZero runtime.

MVAR-first execution boundary with explicit embedded fallback.
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from clawzero.contracts import ActionDecision, ActionRequest
from clawzero.exceptions import ClawZeroConfigError
from clawzero.witness import generate_witness, set_witness_output_dir

logger = logging.getLogger(__name__)


class MVARRuntime:
    """Execution-boundary runtime for agent tool actions."""

    def __init__(
        self,
        profile: str = "dev_balanced",
        witness_dir: Optional[Path] = None,
    ):
        self.profile = profile
        self.witness_dir = witness_dir
        self.last_witness: Optional[dict[str, Any]] = None

        self._mvar_governor: Any = None
        self._mvar_version = "unknown"
        self._mvar_available = self._try_load_mvar()

        if self._mvar_available:
            self.engine = "mvar-security"
            self.policy_id = f"mvar-security.v{self._mvar_version}"
            logger.info("MVAR runtime loaded (mvar-security %s)", self._mvar_version)
        else:
            self.engine = "embedded-policy-v0.1"
            self.policy_id = "mvar-embedded.v0.1"
            logger.warning(
                "MVAR runtime unavailable — using embedded policy engine v0.1"
            )

        self._load_embedded_policy(profile)

        if self.witness_dir is not None:
            set_witness_output_dir(Path(self.witness_dir))

    def engine_info(self) -> dict[str, Any]:
        """Return active engine details for demos and diagnostics."""
        return {
            "engine": self.engine,
            "policy_id": self.policy_id,
            "runtime_available": self._mvar_available,
        }

    def _try_load_mvar(self) -> bool:
        """Try loading mvar-security governor and detect version."""
        try:
            from mvar.governor import ExecutionGovernor  # type: ignore

            try:
                self._mvar_version = version("mvar-security")
            except PackageNotFoundError:
                self._mvar_version = "unknown"

            governor = None
            init_attempts = [
                {"policy_profile": self.profile},
                {"profile": self.profile},
                {},
            ]
            for kwargs in init_attempts:
                try:
                    governor = ExecutionGovernor(**kwargs)
                    break
                except TypeError:
                    continue

            if governor is None:
                governor = ExecutionGovernor()

            if not any(callable(getattr(governor, m, None)) for m in ("evaluate", "decide", "enforce")):
                return False

            self._mvar_governor = governor
            return True
        except Exception:
            self._mvar_governor = None
            return False

    def _load_embedded_policy(self, profile: str) -> None:
        """
        Load minimal deterministic fallback policy.

        Embedded scope intentionally limited to:
        - shell.exec
        - filesystem.read
        - http.request exfiltration controls
        - credentials.access
        """
        if profile not in {"dev_balanced", "dev_strict", "prod_locked"}:
            raise ClawZeroConfigError(f"Unknown policy profile: {profile}")

        self.embedded_policy = {
            "shell.exec": "block",
            "filesystem.read": "profile_sensitive",
            "http.request": "profile_exfil",
            "credentials.access": "block",
        }

    def evaluate(self, request: ActionRequest) -> ActionDecision:
        """Evaluate request through active engine and emit witness."""
        if self._mvar_available:
            decision = self._evaluate_via_mvar(request)
        else:
            decision = self._evaluate_embedded(request)

        self.last_witness = generate_witness(request, decision)
        return decision

    def _evaluate_via_mvar(self, request: ActionRequest) -> ActionDecision:
        """
        MVAR evaluation path.

        If governor output cannot be normalized, safely fallback to embedded
        enforcement for continuity while preserving deterministic behavior.
        """
        governor = self._mvar_governor
        if governor is None:
            return self._evaluate_embedded(request)

        payload = {
            "request_id": request.request_id,
            "sink_type": request.sink_type,
            "target": request.target,
            "arguments": request.arguments,
            "policy_profile": request.policy_profile,
            "prompt_provenance": request.prompt_provenance,
            "framework": request.framework,
        }

        for method_name in ("evaluate", "decide", "enforce"):
            method = getattr(governor, method_name, None)
            if not callable(method):
                continue
            try:
                result = method(payload)
            except TypeError:
                try:
                    result = method(request)
                except Exception:
                    continue
            except Exception:
                continue

            normalized = self._normalize_mvar_result(request, result)
            if normalized is not None:
                return normalized

        fallback = self._evaluate_embedded(request)
        fallback.engine = "embedded-policy-v0.1"
        fallback.policy_id = "mvar-embedded.v0.1"
        return fallback

    def _normalize_mvar_result(
        self, request: ActionRequest, result: Any
    ) -> Optional[ActionDecision]:
        if isinstance(result, ActionDecision):
            result.engine = "mvar-security"
            result.policy_id = f"mvar-security.v{self._mvar_version}"
            if result.target is None:
                result.target = request.target
            return result

        if isinstance(result, dict):
            decision_value = str(result.get("decision", "allow")).lower()
            if decision_value not in {"allow", "block", "annotate"}:
                return None
            return ActionDecision(
                request_id=request.request_id,
                decision=decision_value,
                reason_code=str(result.get("reason_code", "POLICY_ALLOW")),
                human_reason=str(result.get("human_reason", "MVAR policy decision")),
                sink_type=request.sink_type,
                target=request.target,
                policy_profile=self.profile,
                engine="mvar-security",
                policy_id=f"mvar-security.v{self._mvar_version}",
                trust_level=self._derive_trust_level(request),
                annotations={
                    "mvar_result": result,
                    "taint_markers": self._extract_taint_markers(request),
                },
            )

        return None

    def _evaluate_embedded(self, request: ActionRequest) -> ActionDecision:
        sink_type = request.sink_type
        target = request.target or ""

        if sink_type == "shell.exec":
            return self._decision_block(
                request,
                reason_code="UNTRUSTED_TO_CRITICAL_SINK",
                human_reason="MVAR policy blocked shell execution at critical sink",
            )

        if sink_type == "credentials.access":
            return self._decision_block(
                request,
                reason_code="CREDENTIAL_ACCESS_BLOCKED",
                human_reason="MVAR policy blocked credential access sink",
            )

        if sink_type == "filesystem.read":
            return self._evaluate_filesystem_read(request, target)

        if sink_type == "http.request":
            return self._evaluate_http_request(request, target)

        return self._decision_allow(
            request,
            reason_code="POLICY_ALLOW",
            human_reason="MVAR embedded policy allows non-critical sink",
        )

    def _evaluate_filesystem_read(
        self, request: ActionRequest, target: str
    ) -> ActionDecision:
        sensitive_prefixes = (
            "/etc/",
            "/root/.ssh/",
            "/home/user/.ssh/",
            "~/.ssh/",
        )

        if self.profile == "dev_balanced":
            if target.startswith(sensitive_prefixes):
                return self._decision_block(
                    request,
                    reason_code="PATH_BLOCKED",
                    human_reason=f"MVAR policy blocked sensitive read path '{target}'",
                )
            return self._decision_allow(
                request,
                reason_code="ALLOWLIST_MATCH",
                human_reason="MVAR policy allowed non-sensitive read path",
            )

        if self.profile == "dev_strict":
            if target.startswith("/workspace/"):
                return self._decision_allow(
                    request,
                    reason_code="ALLOWLIST_MATCH",
                    human_reason="MVAR strict profile allowed /workspace read",
                )
            return self._decision_block(
                request,
                reason_code="PATH_BLOCKED",
                human_reason="MVAR strict profile blocked read outside /workspace",
            )

        # prod_locked
        if target.startswith("/workspace/project/"):
            return self._decision_allow(
                request,
                reason_code="ALLOWLIST_MATCH",
                human_reason="MVAR prod policy allowed /workspace/project read",
            )
        return self._decision_block(
            request,
            reason_code="PATH_BLOCKED",
            human_reason="MVAR prod policy blocked read outside /workspace/project",
        )

    def _evaluate_http_request(
        self, request: ActionRequest, target: str
    ) -> ActionDecision:
        parsed = urlparse(target)
        hostname = parsed.hostname or target

        if self.profile == "dev_balanced":
            return self._decision_allow(
                request,
                reason_code="POLICY_ALLOW",
                human_reason="MVAR balanced profile allows HTTP request sink",
            )

        if self.profile == "dev_strict":
            return self._decision_block(
                request,
                reason_code="DOMAIN_BLOCKED",
                human_reason="MVAR strict profile blocks HTTP exfiltration sinks",
            )

        # prod_locked
        if hostname in {"localhost", "127.0.0.1"}:
            return self._decision_allow(
                request,
                reason_code="ALLOWLIST_MATCH",
                human_reason="MVAR prod policy allowed localhost HTTP target",
            )

        return self._decision_block(
            request,
            reason_code="DOMAIN_BLOCKED",
            human_reason="MVAR prod policy blocked non-localhost HTTP target",
        )

    def _extract_taint_markers(self, request: ActionRequest) -> list[str]:
        markers = request.prompt_provenance.get("taint_markers")
        if isinstance(markers, list):
            return [str(m) for m in markers]

        taint_level = str(request.prompt_provenance.get("taint_level", "untrusted"))
        if taint_level == "trusted":
            return []
        return ["untrusted_input"]

    def _derive_trust_level(self, request: ActionRequest) -> str:
        taint_level = str(request.prompt_provenance.get("taint_level", "")).lower()
        return "trusted" if taint_level == "trusted" else "untrusted"

    def _decision_block(
        self,
        request: ActionRequest,
        *,
        reason_code: str,
        human_reason: str,
    ) -> ActionDecision:
        return ActionDecision(
            request_id=request.request_id,
            decision="block",
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=self.profile,
            engine="embedded-policy-v0.1",
            policy_id="mvar-embedded.v0.1",
            trust_level=self._derive_trust_level(request),
            annotations={
                "policy_rule_matched": request.sink_type,
                "taint_markers": self._extract_taint_markers(request),
            },
        )

    def _decision_allow(
        self,
        request: ActionRequest,
        *,
        reason_code: str,
        human_reason: str,
    ) -> ActionDecision:
        return ActionDecision(
            request_id=request.request_id,
            decision="allow",
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=self.profile,
            engine="embedded-policy-v0.1",
            policy_id="mvar-embedded.v0.1",
            trust_level=self._derive_trust_level(request),
            annotations={
                "policy_rule_matched": request.sink_type,
                "taint_markers": self._extract_taint_markers(request),
            },
        )

    def emit_witness(self, decision: ActionDecision) -> None:
        """Compatibility no-op; witness emission happens in evaluate()."""
        _ = decision
