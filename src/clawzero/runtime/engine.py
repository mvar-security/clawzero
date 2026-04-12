"""
ClawZero runtime.

MVAR-first execution boundary with explicit embedded fallback.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
from dataclasses import replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from clawzero.contracts import ActionDecision, ActionRequest, InputClass
from clawzero.exceptions import ClawZeroConfigError
from clawzero.witness import generate_witness, set_witness_output_dir

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from clawzero.runtime.session import AgentSession


class MVARRuntime:
    """Execution-boundary runtime for agent tool actions."""

    def __init__(
        self,
        profile: str = "dev_balanced",
        witness_dir: Optional[Path] = None,
        cec_enforce: bool = False,
        network_mode: str = "unrestricted",
        network_allowlist: Optional[list[str]] = None,
        trusted_websocket_origins: Optional[list[str]] = None,
        require_controlplane_auth: bool = True,
        trusted_publishers: Optional[list[str]] = None,
        temporal_taint_mode: str = "warn",
        delayed_taint_threshold_hours: float = 24.0,
        budget_max_cost_usd: Optional[float] = None,
        budget_max_calls_per_window: Optional[int] = None,
        budget_max_calls_per_sink: Optional[int] = None,
        budget_window_seconds: int = 3600,
        budget_charging_policy: str = "SUCCESS_BASED",
        budget_default_cost_usd: float = 0.0,
    ):
        self.profile = profile
        self.witness_dir = witness_dir
        self.cec_enforce = cec_enforce
        self.network_mode = self._normalize_network_mode(network_mode)
        self.network_allowlist = self._normalize_host_set(network_allowlist or [])
        self.trusted_websocket_origins = self._normalize_host_set(
            trusted_websocket_origins or []
        )
        self.require_controlplane_auth = require_controlplane_auth
        self.trusted_publishers = self._normalize_identity_set(trusted_publishers or [])
        self.temporal_taint_mode = self._normalize_temporal_taint_mode(temporal_taint_mode)
        self.delayed_taint_threshold_hours = max(float(delayed_taint_threshold_hours), 0.0)
        self.budget_max_cost_usd = (
            float(budget_max_cost_usd) if budget_max_cost_usd is not None else None
        )
        self.budget_max_calls_per_window = (
            int(budget_max_calls_per_window)
            if budget_max_calls_per_window is not None
            else None
        )
        self.budget_max_calls_per_sink = (
            int(budget_max_calls_per_sink)
            if budget_max_calls_per_sink is not None
            else None
        )
        self.budget_window_seconds = max(int(budget_window_seconds), 1)
        self.budget_charging_policy = self._normalize_budget_charging_policy(
            budget_charging_policy
        )
        self.budget_default_cost_usd = max(float(budget_default_cost_usd), 0.0)
        self.last_witness: Optional[dict[str, Any]] = None
        self._cec_state = {
            "has_private_data": False,
            "has_untrusted_input": False,
            "has_exfil_capability": False,
        }
        self._temporal_taint_state: dict[str, dict[str, datetime]] = {}
        self._budget_state: dict[str, Any] = {
            "window_start": datetime.now(timezone.utc),
            "calls_total": 0,
            "calls_per_sink": {},
            "cost_total_usd": 0.0,
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
            "network_mode": self.network_mode,
            "network_allowlist": sorted(self.network_allowlist),
            "trusted_publishers": sorted(self.trusted_publishers),
            "temporal_taint_mode": self.temporal_taint_mode,
            "delayed_taint_threshold_hours": self.delayed_taint_threshold_hours,
            "budget_enabled": self._budget_enforcement_enabled(),
            "budget_charging_policy": self.budget_charging_policy,
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

        if isinstance(self.last_witness, dict):
            signature = str(self.last_witness.get("witness_signature", ""))
            if signature.startswith("ed25519:"):
                return {
                    "witness_signer": "Ed25519 (native) ✓",
                    "ledger_signer": "N/A (embedded fallback)",
                    "ledger_signer_detail": None,
                }

        return {
            "witness_signer": "ed25519_stub (embedded fallback)",
            "ledger_signer": "N/A (embedded fallback)",
            "ledger_signer_detail": None,
        }

    def _try_load_mvar(self) -> bool:
        """Try loading mvar-security governor and detect version."""
        forced_mode = os.getenv("CLAWZERO_ENGINE_MODE", "").strip().lower()
        if forced_mode in {"embedded", "fallback", "force_embedded"}:
            logger.info("CLAWZERO_ENGINE_MODE=%s forcing embedded engine", forced_mode)
            self._mvar_governor = None
            return False

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
            "websocket.connect": "controlplane_guarded",
            "credentials.access": "block",
        }

    def evaluate(
        self,
        request: ActionRequest,
        session: Optional["AgentSession"] = None,
    ) -> ActionDecision:
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

        decision = self._apply_control_plane_guards(prepared_request, decision)
        decision = self._apply_package_trust_guards(prepared_request, decision)
        decision = self._apply_filesystem_safety_guards(prepared_request, decision)
        decision = self._apply_temporal_taint_guards(prepared_request, decision)
        decision = self._apply_budget_guards(prepared_request, decision)
        decision.annotations["input_class"] = prepared_request.input_class
        decision.annotations["effective_policy_profile"] = prepared_request.policy_profile
        decision.annotations["cec_status"] = cec_status
        decision.annotations["network_mode"] = self.network_mode
        decision.annotations["network_allowlist"] = sorted(self.network_allowlist)
        if not isinstance(decision.annotations.get("provenance"), dict):
            decision.annotations["provenance"] = dict(prepared_request.prompt_provenance)

        if session is not None:
            decision = session.evaluate(decision)

        self.last_witness = generate_witness(prepared_request, decision)
        if session is not None:
            session.attach_witness(self.last_witness)
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
        return request.sink_type in {
            "http.request",
            "filesystem.write",
            "shell.exec",
            "websocket.connect",
        }

    @staticmethod
    def _normalize_network_mode(network_mode: str) -> str:
        value = str(network_mode or "unrestricted").strip().lower()
        allowed = {"unrestricted", "localhost_only", "allowlist_only"}
        if value not in allowed:
            raise ClawZeroConfigError(
                f"Unknown network mode: {network_mode}. Expected one of {sorted(allowed)}"
            )
        return value

    @staticmethod
    def _normalize_temporal_taint_mode(mode: str) -> str:
        value = str(mode or "warn").strip().lower()
        allowed = {"warn", "enforce"}
        if value not in allowed:
            raise ClawZeroConfigError(
                f"Unknown temporal taint mode: {mode}. Expected one of {sorted(allowed)}"
            )
        return value

    @staticmethod
    def _normalize_budget_charging_policy(policy: str) -> str:
        value = str(policy or "SUCCESS_BASED").strip().upper()
        allowed = {"SUCCESS_BASED", "ATTEMPT_BASED"}
        if value not in allowed:
            raise ClawZeroConfigError(
                f"Unknown budget charging policy: {policy}. Expected one of {sorted(allowed)}"
            )
        return value

    def _normalize_host_set(self, values: list[str]) -> set[str]:
        hosts: set[str] = set()
        for value in values:
            host = self._extract_hostname(str(value))
            if host:
                hosts.add(host)
        return hosts

    @staticmethod
    def _normalize_identity_set(values: list[str]) -> set[str]:
        identities: set[str] = set()
        for value in values:
            normalized = str(value or "").strip().lower()
            if normalized:
                identities.add(normalized)
        return identities

    def _extract_hostname(self, value: str | None) -> Optional[str]:
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None
        parsed = urlparse(raw)
        host = parsed.hostname
        if host:
            return host.lower()
        parsed = urlparse(f"//{raw}")
        if parsed.hostname:
            return str(parsed.hostname).lower()
        base = raw.split("/", 1)[0]
        if ":" in base and base.count(":") == 1:
            base = base.split(":", 1)[0]
        return base.lower() if base else None

    @staticmethod
    def _is_localhost(hostname: str | None) -> bool:
        return str(hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}

    def _is_host_allowed_by_network_mode(self, hostname: str | None) -> bool:
        if self.network_mode == "unrestricted":
            return True
        if hostname is None:
            return False
        if self.network_mode == "localhost_only":
            return self._is_localhost(hostname)
        return hostname in self.network_allowlist

    def _extract_origin(self, request: ActionRequest) -> Optional[str]:
        for key in ("origin", "ws_origin", "websocket_origin"):
            value = request.arguments.get(key)
            if value:
                return str(value)

        headers = request.arguments.get("headers")
        if isinstance(headers, dict):
            for key in ("origin", "Origin"):
                if headers.get(key):
                    return str(headers[key])

        for key in ("origin", "ws_origin", "websocket_origin"):
            value = request.metadata.get(key)
            if value:
                return str(value)

        return None

    def _has_controlplane_auth(self, request: ActionRequest) -> bool:
        auth_keys = {
            "auth",
            "auth_token",
            "authorization",
            "token",
            "api_key",
            "session_token",
            "bearer",
        }
        for key in auth_keys:
            value = request.arguments.get(key)
            if isinstance(value, str) and value.strip():
                return True

        headers = request.arguments.get("headers")
        if isinstance(headers, dict):
            for key in ("authorization", "Authorization", "x-api-key", "X-API-Key"):
                value = headers.get(key)
                if isinstance(value, str) and value.strip():
                    return True

        for key in auth_keys:
            value = request.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return True

        return False

    def _is_trusted_websocket_origin(self, origin: Optional[str]) -> bool:
        host = self._extract_hostname(origin)
        if host is None:
            return False
        if self.trusted_websocket_origins:
            return host in self.trusted_websocket_origins
        if self.network_mode == "allowlist_only":
            return host in self.network_allowlist
        if self.network_mode == "localhost_only":
            return self._is_localhost(host)
        # In unrestricted mode, untrusted websocket origins are still bounded.
        return self._is_localhost(host)

    def _override_block_decision(
        self,
        request: ActionRequest,
        decision: ActionDecision,
        *,
        reason_code: str,
        human_reason: str,
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["control_plane_guard"] = True
        annotations["guard_reason_code"] = reason_code
        return ActionDecision(
            request_id=request.request_id,
            decision="block",
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=request.policy_profile,
            engine=decision.engine,
            policy_id=decision.policy_id,
            trust_level=decision.trust_level or self._derive_trust_level(request),
            witness_id=decision.witness_id,
            annotations=annotations,
        )

    def _apply_control_plane_guards(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        if decision.is_blocked():
            return decision

        if request.sink_type == "websocket.connect":
            if self.require_controlplane_auth and not self._has_controlplane_auth(request):
                return self._override_block_decision(
                    request,
                    decision,
                    reason_code="MISSING_CONTROLPLANE_AUTH",
                    human_reason="Control-plane websocket requires explicit auth",
                )

            if self._resolve_input_class(request) == InputClass.UNTRUSTED:
                origin = self._extract_origin(request)
                if not self._is_trusted_websocket_origin(origin):
                    return self._override_block_decision(
                        request,
                        decision,
                        reason_code="UNTRUSTED_WEBSOCKET_ORIGIN",
                        human_reason="Untrusted websocket origin cannot reach control-plane sink",
                    )

        if request.sink_type in {"http.request", "websocket.connect"}:
            target_host = self._extract_hostname(request.target)
            if not self._is_host_allowed_by_network_mode(target_host):
                return self._override_block_decision(
                    request,
                    decision,
                    reason_code="NETWORK_ISOLATION_VIOLATION",
                    human_reason=(
                        f"Network mode '{self.network_mode}' blocked host '{target_host or 'unknown'}'"
                    ),
                )

        return decision

    @staticmethod
    def _normalize_package_source(value: str | None) -> str:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return "unspecified"
        return normalized.replace(" ", "_")

    @staticmethod
    def _optional_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.lower() == "none":
            return None
        return text

    def _package_trust_context(self, request: ActionRequest) -> dict[str, Any]:
        package_source = request.package_source
        if not package_source:
            package_source = self._optional_text(request.metadata.get("package_source"))

        package_hash = request.package_hash
        if not package_hash:
            package_hash = self._optional_text(request.metadata.get("package_hash"))

        package_signature = request.package_signature
        if not package_signature:
            package_signature = self._optional_text(request.metadata.get("package_signature"))

        publisher_id = request.publisher_id
        if not publisher_id:
            publisher_id = self._optional_text(request.metadata.get("publisher_id"))

        normalized_source = self._normalize_package_source(package_source)
        is_marketplace = normalized_source in {
            "marketplace",
            "clawhub",
            "clawhub_marketplace",
            "openclaw_marketplace",
        }
        normalized_publisher = str(publisher_id or "").strip().lower()
        publisher_known = bool(
            normalized_publisher and normalized_publisher in self.trusted_publishers
        )

        return {
            "package_source": normalized_source,
            "package_hash": package_hash,
            "package_signature": package_signature,
            "publisher_id": normalized_publisher or None,
            "signature_present": bool(package_signature),
            "is_marketplace": is_marketplace,
            "strict_profile": request.policy_profile in {"dev_strict", "prod_locked"},
            "publisher_known": publisher_known,
        }

    def _with_package_context(
        self, decision: ActionDecision, package_context: dict[str, Any]
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["package_trust"] = package_context
        return replace(decision, annotations=annotations)

    def _override_package_decision(
        self,
        request: ActionRequest,
        decision: ActionDecision,
        *,
        decision_value: str,
        reason_code: str,
        human_reason: str,
        enforcement_action: str | None = None,
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["package_trust_guard"] = True
        annotations["guard_reason_code"] = reason_code
        if enforcement_action:
            annotations["enforcement_action"] = enforcement_action
        package_trust = annotations.get("package_trust")
        if isinstance(package_trust, dict):
            package_trust["policy_outcome"] = reason_code
            package_trust["policy_decision"] = decision_value

        return ActionDecision(
            request_id=request.request_id,
            decision=decision_value,
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=request.policy_profile,
            engine=decision.engine,
            policy_id=decision.policy_id,
            trust_level=decision.trust_level or self._derive_trust_level(request),
            witness_id=decision.witness_id,
            annotations=annotations,
        )

    def _apply_package_trust_guards(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        package_context = self._package_trust_context(request)
        decision = self._with_package_context(decision, package_context)

        if not package_context["is_marketplace"]:
            return decision

        if (
            request.policy_profile == "prod_locked"
            and not package_context["signature_present"]
        ):
            return self._override_package_decision(
                request,
                decision,
                decision_value="block",
                reason_code="UNSIGNED_MARKETPLACE_PACKAGE",
                human_reason="Unsigned marketplace package blocked in prod_locked profile",
            )

        if (
            package_context["strict_profile"]
            and not package_context["publisher_known"]
            and not decision.is_blocked()
        ):
            return self._override_package_decision(
                request,
                decision,
                decision_value="annotate",
                reason_code="UNKNOWN_PUBLISHER_STEP_UP",
                human_reason="Unknown marketplace publisher requires step-up approval",
                enforcement_action="block_until_approved",
            )

        return decision

    @staticmethod
    def _parse_iso_timestamp(value: Any) -> Optional[datetime]:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_iso_timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    def _temporal_taint_key(self, request: ActionRequest) -> str:
        provenance = request.prompt_provenance
        custom_key = self._optional_text(provenance.get("taint_id"))
        if custom_key:
            return custom_key
        source_chain = provenance.get("source_chain")
        if isinstance(source_chain, list) and source_chain:
            return "chain:" + "->".join(str(item) for item in source_chain)
        return "source:" + str(provenance.get("source", "unknown_source"))

    def _temporal_taint_status(self, request: ActionRequest) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        provenance = request.prompt_provenance
        source_chain = provenance.get("source_chain")
        if not isinstance(source_chain, list):
            source_chain = [str(provenance.get("source", "unknown_source"))]
        source_chain_text = [str(item) for item in source_chain]
        taint_markers = provenance.get("taint_markers")
        if not isinstance(taint_markers, list):
            taint_markers = []
        taint_markers_text = [str(item) for item in taint_markers]

        state_key = self._temporal_taint_key(request)
        state = self._temporal_taint_state.get(state_key)
        first_seen_hint = self._parse_iso_timestamp(
            provenance.get("first_seen_at") or provenance.get("first_seen_timestamp")
        )
        last_propagated_hint = self._parse_iso_timestamp(
            provenance.get("last_propagated_at")
            or provenance.get("last_propagated_timestamp")
        )

        if state is None:
            first_seen = first_seen_hint or now
            last_propagated = max(
                first_seen,
                last_propagated_hint or now,
            )
        else:
            first_seen = state["first_seen"]
            if first_seen_hint is not None:
                first_seen = min(first_seen, first_seen_hint)
            last_propagated = max(
                state["last_propagated"],
                last_propagated_hint or now,
                now,
            )

        self._temporal_taint_state[state_key] = {
            "first_seen": first_seen,
            "last_propagated": last_propagated,
        }

        taint_age_hours = max((now - first_seen).total_seconds() / 3600.0, 0.0)
        has_memory_trace = any("memory" in item.lower() for item in source_chain_text) or any(
            marker.lower() in {"persistent_memory", "memory_injection", "delayed_execution"}
            for marker in taint_markers_text
        )
        is_untrusted = self._resolve_input_class(request) == InputClass.UNTRUSTED
        delayed_trigger_detected = bool(
            is_untrusted
            and has_memory_trace
            and taint_age_hours >= self.delayed_taint_threshold_hours
        )

        return {
            "state_key": state_key,
            "mode": self.temporal_taint_mode,
            "threshold_hours": self.delayed_taint_threshold_hours,
            "first_seen_timestamp": self._format_iso_timestamp(first_seen),
            "last_propagated_timestamp": self._format_iso_timestamp(last_propagated),
            "taint_age_hours": round(taint_age_hours, 3),
            "has_memory_trace": has_memory_trace,
            "delayed_trigger_detected": delayed_trigger_detected,
        }

    def _with_temporal_status(
        self, decision: ActionDecision, temporal_status: dict[str, Any]
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["temporal_taint_status"] = temporal_status
        annotations["delayed_trigger_detected"] = temporal_status[
            "delayed_trigger_detected"
        ]
        annotations["taint_age_hours"] = temporal_status["taint_age_hours"]
        return replace(decision, annotations=annotations)

    def _override_temporal_decision(
        self,
        request: ActionRequest,
        decision: ActionDecision,
        *,
        reason_code: str,
        human_reason: str,
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["temporal_taint_guard"] = True
        annotations["guard_reason_code"] = reason_code
        return ActionDecision(
            request_id=request.request_id,
            decision="block",
            reason_code=reason_code,
            human_reason=human_reason,
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=request.policy_profile,
            engine=decision.engine,
            policy_id=decision.policy_id,
            trust_level=decision.trust_level or self._derive_trust_level(request),
            witness_id=decision.witness_id,
            annotations=annotations,
        )

    def _apply_filesystem_safety_guards(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        """
        Enforce deterministic path safety constraints for filesystem reads.

        This guard closes traversal/encoding bypass cases even when upstream
        governor policies are permissive.
        """
        if request.sink_type != "filesystem.read":
            return decision

        if decision.decision == "block":
            return decision

        target = str(request.target or "")
        target_lower = target.lower()

        traversal_tokens = (
            "../",
            "..\\",
            "%2e%2e",
            "%2f",
            "%5c",
            "%32%65",
            "\x00",
        )
        sensitive_prefixes = (
            "/etc/",
            "/proc/",
            "/root/",
            "/home/",
            "~/.ssh/",
            "/users/",
        )

        has_traversal_signal = any(token in target_lower for token in traversal_tokens)
        is_sensitive_target = target_lower.startswith(sensitive_prefixes)

        profile = request.policy_profile or self.profile

        if profile == "prod_locked":
            if (
                has_traversal_signal
                or is_sensitive_target
                or not target_lower.startswith("/workspace/project/")
            ):
                return self._decision_block(
                    request,
                    reason_code="PATH_BLOCKED",
                    human_reason="MVAR prod policy blocked unsafe filesystem read path",
                )
            return decision

        if profile == "dev_strict":
            if (
                has_traversal_signal
                or is_sensitive_target
                or not target_lower.startswith("/workspace/")
            ):
                return self._decision_block(
                    request,
                    reason_code="PATH_BLOCKED",
                    human_reason="MVAR strict policy blocked unsafe filesystem read path",
                )
            return decision

        if profile == "dev_balanced" and (has_traversal_signal or is_sensitive_target):
            return self._decision_block(
                request,
                reason_code="PATH_BLOCKED",
                human_reason="MVAR balanced policy blocked unsafe filesystem read path",
            )

        return decision

    def _apply_temporal_taint_guards(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        temporal_status = self._temporal_taint_status(request)
        decision = self._with_temporal_status(decision, temporal_status)

        if (
            self.temporal_taint_mode == "enforce"
            and temporal_status["delayed_trigger_detected"]
            and not decision.is_blocked()
        ):
            return self._override_temporal_decision(
                request,
                decision,
                reason_code="DELAYED_TAINT_TRIGGER",
                human_reason=(
                    "Delayed untrusted memory trigger blocked by temporal taint enforcement"
                ),
            )

        return decision

    def _budget_enforcement_enabled(self) -> bool:
        limits = (
            self.budget_max_cost_usd,
            self.budget_max_calls_per_window,
            self.budget_max_calls_per_sink,
        )
        return any(limit is not None for limit in limits)

    def _budget_reset_if_needed(self, now: datetime) -> None:
        window_start = self._budget_state["window_start"]
        elapsed = (now - window_start).total_seconds()
        if elapsed < self.budget_window_seconds:
            return
        self._budget_state = {
            "window_start": now,
            "calls_total": 0,
            "calls_per_sink": {},
            "cost_total_usd": 0.0,
        }

    def _budget_request_cost_usd(self, request: ActionRequest) -> float:
        candidates = (
            request.metadata.get("cost_usd"),
            request.metadata.get("estimated_cost_usd"),
            request.arguments.get("cost_usd"),
        )
        for value in candidates:
            if value is None:
                continue
            try:
                return max(float(value), 0.0)
            except (TypeError, ValueError):
                continue
        return self.budget_default_cost_usd

    def _with_budget_status(
        self, decision: ActionDecision, budget_status: dict[str, Any]
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["budget_status"] = budget_status
        return replace(decision, annotations=annotations)

    def _override_budget_decision(
        self,
        request: ActionRequest,
        decision: ActionDecision,
        *,
        budget_status: dict[str, Any],
    ) -> ActionDecision:
        annotations = dict(decision.annotations)
        annotations["budget_guard"] = True
        annotations["budget_status"] = budget_status
        exceeded = budget_status.get("exceeded_limits") or ["configured_budget_limit"]
        return ActionDecision(
            request_id=request.request_id,
            decision="block",
            reason_code="BUDGET_LIMIT_EXCEEDED",
            human_reason="Budget policy blocked request due to: " + ", ".join(exceeded),
            sink_type=request.sink_type,
            target=request.target,
            policy_profile=request.policy_profile,
            engine=decision.engine,
            policy_id=decision.policy_id,
            trust_level=decision.trust_level or self._derive_trust_level(request),
            witness_id=decision.witness_id,
            annotations=annotations,
        )

    def _apply_budget_guards(
        self, request: ActionRequest, decision: ActionDecision
    ) -> ActionDecision:
        now = datetime.now(timezone.utc)
        self._budget_reset_if_needed(now)
        budget_enabled = self._budget_enforcement_enabled()
        charge_applied = False
        request_cost = 0.0

        if budget_enabled:
            if self.budget_charging_policy == "ATTEMPT_BASED":
                charge_applied = True
            else:
                charge_applied = decision.decision == "allow"

        if charge_applied:
            request_cost = self._budget_request_cost_usd(request)
            self._budget_state["calls_total"] += 1
            sink_calls = self._budget_state["calls_per_sink"]
            sink_calls[request.sink_type] = int(sink_calls.get(request.sink_type, 0)) + 1
            self._budget_state["cost_total_usd"] += request_cost

        sink_calls_count = int(
            self._budget_state["calls_per_sink"].get(request.sink_type, 0)
        )
        exceeded_limits: list[str] = []
        if (
            self.budget_max_calls_per_window is not None
            and self._budget_state["calls_total"] > self.budget_max_calls_per_window
        ):
            exceeded_limits.append("max_calls_per_window")
        if (
            self.budget_max_calls_per_sink is not None
            and sink_calls_count > self.budget_max_calls_per_sink
        ):
            exceeded_limits.append("max_calls_per_sink")
        if (
            self.budget_max_cost_usd is not None
            and self._budget_state["cost_total_usd"] > self.budget_max_cost_usd
        ):
            exceeded_limits.append("max_cost_usd")

        budget_status = {
            "enabled": budget_enabled,
            "charging_policy": self.budget_charging_policy,
            "charge_applied": charge_applied,
            "request_cost_usd": round(request_cost, 6),
            "window_start": self._format_iso_timestamp(self._budget_state["window_start"]),
            "window_seconds": self.budget_window_seconds,
            "calls_total": self._budget_state["calls_total"],
            "calls_for_sink": sink_calls_count,
            "cost_total_usd": round(float(self._budget_state["cost_total_usd"]), 6),
            "limits": {
                "max_cost_usd": self.budget_max_cost_usd,
                "max_calls_per_window": self.budget_max_calls_per_window,
                "max_calls_per_sink": self.budget_max_calls_per_sink,
            },
            "exceeded_limits": exceeded_limits,
        }

        decision = self._with_budget_status(decision, budget_status)

        if budget_enabled and charge_applied and exceeded_limits and not decision.is_blocked():
            return self._override_budget_decision(
                request,
                decision,
                budget_status=budget_status,
            )

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
            "package_source": request.package_source,
            "package_hash": request.package_hash,
            "package_signature": request.package_signature,
            "publisher_id": request.publisher_id,
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
