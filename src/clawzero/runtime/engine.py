"""
ClawZero runtime.

MVAR-first execution boundary with explicit embedded fallback.
"""

from __future__ import annotations

import contextlib
import io
import logging
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from clawzero.contracts import ActionDecision, ActionRequest, InputClass
from clawzero.exceptions import ClawZeroConfigError
from clawzero.witness import generate_witness, set_witness_output_dir

logger = logging.getLogger(__name__)


class MVARRuntime:
    """Execution-boundary runtime for agent tool actions."""

    def __init__(
        self,
        profile: str = "dev_balanced",
        witness_dir: Optional[Path] = None,
        cec_enforce: bool = False,
    ):
        self.profile = profile
        self.witness_dir = witness_dir
        self.cec_enforce = cec_enforce
        self.last_witness: Optional[dict[str, Any]] = None
        self._cec_state = {
            "has_private_data": False,
            "has_untrusted_input": False,
            "has_exfil_capability": False,
        }

        self._mvar_governor: Any = None
        self._mvar_version = "unknown"
        self._witness_signer = "ed25519_stub"
        self._ledger_signer = "embedded"
        self._mvar_available = self._try_load_mvar()

        if self._mvar_available:
            self.engine = "mvar-security"
            self.policy_id = f"mvar-security.v{self._mvar_version}"
            self._witness_signer = "ed25519_qseal"
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
        signer = self.signer_info()
        return {
            "engine": self.engine,
            "policy_id": self.policy_id,
            "runtime_available": self._mvar_available,
            "witness_signer": signer["witness_signer"],
            "ledger_signer": signer["ledger_signer"],
            "ledger_signer_detail": signer["ledger_signer_detail"],
        }

    def signer_info(self) -> dict[str, str | None]:
        """Return user-facing signer status for witness and decision ledger."""
        if self._mvar_available:
            if self._ledger_signer == "hmac_fallback":
                return {
                    "witness_signer": "Ed25519 (QSEAL) ✓",
                    "ledger_signer": "HMAC fallback",
                    "ledger_signer_detail": "(external signer not configured)",
                }

            return {
                "witness_signer": "Ed25519 (QSEAL) ✓",
                "ledger_signer": "Ed25519 (QSEAL) ✓",
                "ledger_signer_detail": None,
            }

        return {
            "witness_signer": "ed25519_stub (embedded fallback)",
            "ledger_signer": "N/A (embedded fallback)",
            "ledger_signer_detail": None,
        }

    def _try_load_mvar(self) -> bool:
        """Try loading mvar-security governor and detect version."""
        try:
            captured_output = io.StringIO()
            with contextlib.redirect_stdout(captured_output), contextlib.redirect_stderr(
                captured_output
            ):
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

                if not any(
                    callable(getattr(governor, method_name, None))
                    for method_name in ("evaluate", "decide", "enforce")
                ):
                    return False

            bootstrap_log = captured_output.getvalue()
            if logger.isEnabledFor(logging.DEBUG) and bootstrap_log.strip():
                logger.debug("mvar-security bootstrap output: %s", bootstrap_log.strip())
            self._ledger_signer = self._detect_ledger_signer()
            self._mvar_governor = governor
            return True
        except Exception:
            self._mvar_governor = None
            return False

    def _detect_ledger_signer(self) -> str:
        """
        Detect the decision-ledger signer mode from the installed mvar runtime.

        This is independent from witness signing, which remains Ed25519/QSEAL.
        """
        try:
            from mvar_core import decision_ledger  # type: ignore

            mode = str(getattr(decision_ledger, "QSEAL_MODE", "")).strip().lower()
            if mode == "hmac-sha256":
                return "hmac_fallback"
            if mode:
                return "ed25519_qseal"
        except Exception:
            pass

        return "unknown"

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
        prepared_request = self._prepare_request(request)

        if self._mvar_available:
            decision = self._evaluate_via_mvar(prepared_request)
        else:
            decision = self._evaluate_embedded(prepared_request)

        cec_status = self._update_cec_state(prepared_request)
        if (
            self.cec_enforce
            and cec_status["cec_triggered"]
            and prepared_request.policy_profile != "prod_locked"
        ):
            prepared_request = replace(prepared_request, policy_profile="prod_locked")
            if self._mvar_available:
                decision = self._evaluate_via_mvar(prepared_request)
            else:
                decision = self._evaluate_embedded(prepared_request)
            decision.annotations["cec_escalated_profile"] = "prod_locked"

        decision.annotations["input_class"] = prepared_request.input_class
        decision.annotations["effective_policy_profile"] = prepared_request.policy_profile
        decision.annotations["cec_status"] = cec_status

        self.last_witness = generate_witness(prepared_request, decision)
        return decision

    def _prepare_request(self, request: ActionRequest) -> ActionRequest:
        input_class = self._resolve_input_class(request)
        normalized_profile = self._apply_input_class_overrides(
            request.policy_profile, input_class
        )

        provenance = dict(request.prompt_provenance or {})
        source = str(provenance.get("source", "unknown_source"))
        taint_markers = provenance.get("taint_markers")
        if not isinstance(taint_markers, list):
            taint_markers = []
        source_chain = provenance.get("source_chain")
        if not isinstance(source_chain, list) or not source_chain:
            source_chain = [source, request.action_type]

        provenance["source"] = source
        provenance["taint_level"] = (
            "trusted"
            if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
            else "untrusted"
        )
        provenance["taint_markers"] = [str(item) for item in taint_markers]
        provenance["source_chain"] = [str(item) for item in source_chain]

        return replace(
            request,
            input_class=input_class.value,
            prompt_provenance=provenance,
            policy_profile=normalized_profile,
        )

    def _resolve_input_class(self, request: ActionRequest) -> InputClass:
        raw_value = str(request.input_class or "").strip().lower()
        if raw_value in {member.value for member in InputClass}:
            return InputClass(raw_value)

        taint_level = str(request.prompt_provenance.get("taint_level", "")).strip().lower()
        if taint_level in {"trusted", "clean"}:
            return InputClass.TRUSTED
        if taint_level in {"pre_authorized", "pre-authorized"}:
            return InputClass.PRE_AUTHORIZED
        return InputClass.UNTRUSTED

    def _apply_input_class_overrides(self, profile: str, input_class: InputClass) -> str:
        if input_class == InputClass.UNTRUSTED and profile == "dev_balanced":
            return "dev_strict"
        return profile

    def _update_cec_state(self, request: ActionRequest) -> dict[str, bool]:
        if self._is_private_data_sink(request):
            self._cec_state["has_private_data"] = True
        if self._is_untrusted_request(request):
            self._cec_state["has_untrusted_input"] = True
        if self._is_exfil_capability_sink(request):
            self._cec_state["has_exfil_capability"] = True

        return {
            "has_private_data": self._cec_state["has_private_data"],
            "has_untrusted_input": self._cec_state["has_untrusted_input"],
            "has_exfil_capability": self._cec_state["has_exfil_capability"],
            "cec_triggered": all(self._cec_state.values()),
        }

    def _is_untrusted_request(self, request: ActionRequest) -> bool:
        if self._resolve_input_class(request) == InputClass.UNTRUSTED:
            return True
        taint = str(request.prompt_provenance.get("taint_level", "")).lower()
        return taint == "untrusted"

    def _is_private_data_sink(self, request: ActionRequest) -> bool:
        if request.sink_type == "credentials.access":
            return True
        if request.sink_type != "filesystem.read":
            return False
        target = str(request.target or "").lower()
        sensitive_tokens = (
            "/etc/",
            "/.ssh/",
            ".env",
            "id_rsa",
            "credentials",
            "secret",
            "token",
            "password",
        )
        return any(token in target for token in sensitive_tokens)

    def _is_exfil_capability_sink(self, request: ActionRequest) -> bool:
        return request.sink_type in {"http.request", "filesystem.write", "shell.exec"}

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
        if (
            hasattr(result, "decision")
            and hasattr(result, "reason_code")
            and hasattr(result, "policy_id")
            and hasattr(result, "engine")
        ):
            decision_value = str(getattr(result, "decision", "allow")).lower()
            if decision_value not in {"allow", "block", "annotate"}:
                return None
            provenance = getattr(result, "provenance", {})
            if not isinstance(provenance, dict):
                provenance = {}
            trace = getattr(result, "evaluation_trace", [])
            if not isinstance(trace, list):
                trace = []
            witness_signature = str(getattr(result, "witness_signature", "") or "")
            trust_level = str(provenance.get("taint_level", "")).lower() or self._derive_trust_level(request)
            enforcement_action = getattr(result, "enforcement_action", None)
            annotations = {
                "witness_signature": witness_signature,
                "provenance": provenance,
                "evaluation_trace": [str(item) for item in trace],
                "enforcement_action": enforcement_action,
                "taint_markers": self._extract_taint_markers(request),
            }
            decision = ActionDecision(
                request_id=request.request_id,
                decision=decision_value,
                reason_code=str(getattr(result, "reason_code", "POLICY_ALLOW")),
                human_reason=str(
                    getattr(result, "human_reason", "")
                    or f"MVAR policy decision: {getattr(result, 'reason_code', 'POLICY_ALLOW')}"
                ),
                sink_type=request.sink_type,
                target=request.target,
                policy_profile=request.policy_profile,
                engine=str(getattr(result, "engine", "mvar-security")),
                policy_id=str(getattr(result, "policy_id", f"mvar-security.v{self._mvar_version}")),
                trust_level="trusted" if trust_level == "trusted" else "untrusted",
                annotations=annotations,
            )
            return self._apply_mvar_compatibility_overrides(request, decision)

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
            decision = ActionDecision(
                request_id=request.request_id,
                decision=decision_value,
                reason_code=str(result.get("reason_code", "POLICY_ALLOW")),
                human_reason=str(result.get("human_reason", "MVAR policy decision")),
                sink_type=request.sink_type,
                target=request.target,
                policy_profile=request.policy_profile,
                engine="mvar-security",
                policy_id=f"mvar-security.v{self._mvar_version}",
                trust_level=self._derive_trust_level(request),
                annotations={
                    "mvar_result": result,
                    "witness_signature": str(result.get("witness_signature", "")),
                    "provenance": result.get("provenance", {}),
                    "evaluation_trace": result.get("evaluation_trace", []),
                    "enforcement_action": result.get("enforcement_action"),
                    "taint_markers": self._extract_taint_markers(request),
                },
            )
            return self._apply_mvar_compatibility_overrides(request, decision)

        return None

    def _apply_mvar_compatibility_overrides(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        """
        Keep historical ClawZero behavior stable when MVAR policies are stricter.
        """
        if decision.decision != "block":
            return decision

        if decision.reason_code not in {"POLICY_BLOCK", "POLICY_DENY", "POLICY_REJECT"}:
            return decision

        request_class = self._resolve_input_class(request)

        if (
            request.sink_type == "tool.custom"
            and request_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
        ):
            decision.decision = "allow"
            decision.reason_code = "POLICY_ALLOW"
            decision.human_reason = (
                "Trusted custom tool request allowed by ClawZero compatibility policy"
            )
            decision.annotations["compatibility_override"] = "trusted_tool_custom_allow"
            return decision

        if (
            request.sink_type == "tool.custom"
            and request.policy_profile in {"dev_balanced", "dev_strict"}
            and request_class == InputClass.UNTRUSTED
        ):
            decision.decision = "annotate"
            decision.reason_code = "STEP_UP_REQUIRED"
            decision.human_reason = (
                "ClawZero compatibility policy requires step-up review for untrusted custom sink"
            )
            decision.annotations["enforcement_action"] = "block_until_approved"
            decision.annotations["compatibility_override"] = "dev_balanced_tool_custom_step_up"
            return decision

        if (
            request.sink_type == "filesystem.read"
            and request.policy_profile == "prod_locked"
            and request_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
            and str(request.target or "").startswith("/workspace/project/")
        ):
            decision.decision = "allow"
            decision.reason_code = "ALLOWLIST_MATCH"
            decision.human_reason = (
                "Trusted workspace read allowed by ClawZero compatibility policy"
            )
            decision.annotations["compatibility_override"] = "prod_locked_workspace_read_allow"

        return decision

    def _evaluate_embedded(self, request: ActionRequest) -> ActionDecision:
        sink_type = request.sink_type
        target = request.target or ""
        input_class = self._resolve_input_class(request)
        active_profile = request.policy_profile or self.profile

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
            return self._evaluate_filesystem_read(request, target, active_profile)

        if sink_type == "http.request":
            return self._evaluate_http_request(request, target, active_profile)

        if sink_type == "tool.custom":
            if active_profile == "dev_strict":
                if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}:
                    return self._decision_allow(
                        request,
                        reason_code="POLICY_ALLOW",
                        human_reason="MVAR strict profile allowed trusted custom tool sink",
                    )
                return self._decision_annotate(
                    request,
                    reason_code="STEP_UP_REQUIRED",
                    human_reason="MVAR strict profile requires review for untrusted custom sink",
                    enforcement_action="block_until_approved",
                )

            if active_profile == "dev_balanced" and input_class == InputClass.UNTRUSTED:
                return self._decision_annotate(
                    request,
                    reason_code="STEP_UP_REQUIRED",
                    human_reason="MVAR balanced profile requires review for untrusted custom sink",
                    enforcement_action="block_until_approved",
                )

        return self._decision_allow(
            request,
            reason_code="POLICY_ALLOW",
            human_reason="MVAR embedded policy allows non-critical sink",
        )

    def _evaluate_filesystem_read(
        self, request: ActionRequest, target: str, active_profile: str
    ) -> ActionDecision:
        sensitive_prefixes = (
            "/etc/",
            "/root/.ssh/",
            "/home/user/.ssh/",
            "~/.ssh/",
        )

        if active_profile == "dev_balanced":
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

        if active_profile == "dev_strict":
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
        self, request: ActionRequest, target: str, active_profile: str
    ) -> ActionDecision:
        parsed = urlparse(target)
        hostname = parsed.hostname or target

        if active_profile == "dev_balanced":
            return self._decision_allow(
                request,
                reason_code="POLICY_ALLOW",
                human_reason="MVAR balanced profile allows HTTP request sink",
            )

        if active_profile == "dev_strict":
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
        input_class = self._resolve_input_class(request)
        if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}:
            return "trusted"
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
            policy_profile=request.policy_profile,
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
            policy_profile=request.policy_profile,
            engine="embedded-policy-v0.1",
            policy_id="mvar-embedded.v0.1",
            trust_level=self._derive_trust_level(request),
            annotations={
                "policy_rule_matched": request.sink_type,
                "taint_markers": self._extract_taint_markers(request),
            },
        )

    def _decision_annotate(
        self,
        request: ActionRequest,
        *,
        reason_code: str,
        human_reason: str,
        enforcement_action: str,
    ) -> ActionDecision:
        return ActionDecision(
            request_id=request.request_id,
            decision="annotate",
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=request.policy_profile,
            engine="embedded-policy-v0.1",
            policy_id="mvar-embedded.v0.1",
            trust_level=self._derive_trust_level(request),
            annotations={
                "policy_rule_matched": request.sink_type,
                "taint_markers": self._extract_taint_markers(request),
                "enforcement_action": enforcement_action,
            },
        )

    def emit_witness(self, decision: ActionDecision) -> None:
        """Compatibility no-op; witness emission happens in evaluate()."""
        _ = decision
