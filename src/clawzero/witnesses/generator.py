"""
ClawZero witness generation.

Every enforcement decision emits a signed witness artifact.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from clawzero.contracts import ActionDecision, ActionRequest


class WitnessGenerator:
    """Generates canonical witness artifacts."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0
        self._last_content_hash: Optional[str] = None
        self._last_chain_index = 0
        self._ed25519_private_key: Any | None = None
        self._signing_mode = "ed25519_stub"
        self._initialize_signer()

    def generate(self, request: ActionRequest, decision: ActionDecision) -> dict:
        witness_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        chain_index, previous_hash = self._resolve_chain_state()

        source_chain = self._extract_source_chain(request)
        taint_markers = self._extract_taint_markers(request, decision)
        cec_status = self._extract_cec_status(decision)
        package_trust = self._extract_package_trust(request, decision)
        temporal_taint_status = self._extract_temporal_taint_status(decision)
        budget_status = self._extract_budget_status(decision)

        adapter_metadata = request.metadata.get(
            "adapter",
            {
                "name": request.framework,
                "mode": "tool_wrap",
                "framework": request.framework,
            },
        )

        witness = {
            "schema_version": "1.1",
            "chain_index": chain_index,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "agent_runtime": request.framework,
            "sink_type": decision.sink_type,
            "target": decision.target,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "policy_id": decision.policy_id,
            "provenance": {
                "source": str(request.prompt_provenance.get("source", "unknown_source")),
                "taint_level": str(request.prompt_provenance.get("taint_level", decision.trust_level or "unknown")),
                "source_chain": source_chain,
                "taint_markers": taint_markers,
            },
            "input_class": str(request.input_class),
            "cec_status": cec_status,
            "package_trust": package_trust,
            "temporal_taint_status": temporal_taint_status,
            "delayed_trigger_detected": bool(
                temporal_taint_status.get("delayed_trigger_detected", False)
            ),
            "taint_age_hours": temporal_taint_status.get("taint_age_hours", 0.0),
            "budget_status": budget_status,
            "witness_signature": self._sign(witness_id, request, decision),
            "engine": decision.engine,
            "adapter": adapter_metadata,
            "witness_id": witness_id,
            # Compatibility fields retained for existing integrations.
            "request_id": request.request_id,
            "framework": request.framework,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
            "action": {
                "type": request.action_type,
                "sink_type": decision.sink_type,
                "tool_name": request.tool_name,
                "target": decision.target,
                "arguments": request.arguments,
            },
            "decision_detail": {
                "result": decision.decision,
                "reason_code": decision.reason_code,
                "human_reason": decision.human_reason,
                "policy_profile": decision.policy_profile,
                "policy_id": decision.policy_id,
                "engine": decision.engine,
            },
            "annotations": decision.annotations,
        }

        # P1 Continuity Metadata Attestation
        # Emit top-level continuity section from governor's continuity_metadata
        continuity_metadata = decision.annotations.get("continuity_metadata")
        if continuity_metadata and isinstance(continuity_metadata, dict):
            witness["continuity"] = {
                "continuity_hash": continuity_metadata.get("continuity_hash"),
                "protocol_version": continuity_metadata.get("protocol_version"),
                "constitutional_classification": continuity_metadata.get("constitutional_classification"),
                "ccl_source": continuity_metadata.get("ccl_source"),
                "violation_count": continuity_metadata.get("violation_count", 0),
            }

        witness["content_hash"] = self._content_hash(witness)

        decision.witness_id = witness_id
        self._last_chain_index = chain_index
        self._last_content_hash = witness["content_hash"]

        if self.output_dir:
            self._persist(witness)

        return witness

    def _extract_source_chain(self, request: ActionRequest) -> list[str]:
        chain = request.prompt_provenance.get("source_chain")
        if isinstance(chain, list) and chain:
            return [str(item) for item in chain]

        source = request.prompt_provenance.get("source", "unknown_source")
        return [str(source), request.action_type]

    def _extract_taint_markers(
        self, request: ActionRequest, decision: ActionDecision
    ) -> list[str]:
        markers = request.prompt_provenance.get("taint_markers")
        if isinstance(markers, list):
            return [str(item) for item in markers]

        decision_markers = decision.annotations.get("taint_markers")
        if isinstance(decision_markers, list):
            return [str(item) for item in decision_markers]

        return []

    @staticmethod
    def _extract_cec_status(decision: ActionDecision) -> dict[str, bool]:
        fallback = {
            "has_private_data": False,
            "has_untrusted_input": False,
            "has_exfil_capability": False,
            "cec_triggered": False,
        }
        raw = decision.annotations.get("cec_status")
        if not isinstance(raw, dict):
            return fallback

        return {
            "has_private_data": bool(raw.get("has_private_data", False)),
            "has_untrusted_input": bool(raw.get("has_untrusted_input", False)),
            "has_exfil_capability": bool(raw.get("has_exfil_capability", False)),
            "cec_triggered": bool(raw.get("cec_triggered", False)),
        }

    @staticmethod
    def _extract_package_trust(
        request: ActionRequest, decision: ActionDecision
    ) -> dict[str, Any]:
        def _optional_text(value: Any) -> str | None:
            if value is None:
                return None
            text = str(value).strip()
            if not text or text.lower() == "none":
                return None
            return text

        raw = decision.annotations.get("package_trust")
        package_trust: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
        fallback_source = _optional_text(request.package_source)
        if fallback_source is None:
            fallback_source = _optional_text(request.metadata.get("package_source"))
        if fallback_source is None:
            fallback_source = "unspecified"
        package_trust.setdefault(
            "package_source",
            fallback_source,
        )
        package_trust.setdefault(
            "package_hash",
            _optional_text(request.package_hash)
            or _optional_text(request.metadata.get("package_hash")),
        )
        package_trust.setdefault(
            "package_signature",
            _optional_text(request.package_signature)
            or _optional_text(request.metadata.get("package_signature")),
        )
        package_trust.setdefault(
            "publisher_id",
            _optional_text(request.publisher_id)
            or _optional_text(request.metadata.get("publisher_id")),
        )
        package_trust.setdefault("policy_reason", decision.reason_code)
        package_trust.setdefault("policy_decision", decision.decision)
        return package_trust

    @staticmethod
    def _extract_temporal_taint_status(decision: ActionDecision) -> dict[str, Any]:
        fallback = {
            "mode": "warn",
            "threshold_hours": 24.0,
            "first_seen_timestamp": None,
            "last_propagated_timestamp": None,
            "taint_age_hours": 0.0,
            "has_memory_trace": False,
            "delayed_trigger_detected": False,
        }
        raw = decision.annotations.get("temporal_taint_status")
        if not isinstance(raw, dict):
            return fallback

        status = dict(raw)
        for key, value in fallback.items():
            status.setdefault(key, value)
        return status

    @staticmethod
    def _extract_budget_status(decision: ActionDecision) -> dict[str, Any]:
        fallback = {
            "enabled": False,
            "charging_policy": "SUCCESS_BASED",
            "charge_applied": False,
            "request_cost_usd": 0.0,
            "calls_total": 0,
            "calls_for_sink": 0,
            "cost_total_usd": 0.0,
            "limits": {
                "max_cost_usd": None,
                "max_calls_per_window": None,
                "max_calls_per_sink": None,
            },
            "exceeded_limits": [],
        }
        raw = decision.annotations.get("budget_status")
        if not isinstance(raw, dict):
            return fallback
        status = dict(raw)
        for key, value in fallback.items():
            status.setdefault(key, value)
        if not isinstance(status.get("limits"), dict):
            status["limits"] = {
                "max_cost_usd": None,
                "max_calls_per_window": None,
                "max_calls_per_sink": None,
            }
        if not isinstance(status.get("exceeded_limits"), list):
            status["exceeded_limits"] = []
        return status

    def _sign(
        self, witness_id: str, request: ActionRequest, decision: ActionDecision
    ) -> str:
        existing_signature = decision.annotations.get("witness_signature")
        if isinstance(existing_signature, str) and existing_signature:
            return existing_signature

        mvar_signature = decision.annotations.get("mvar_result", {}).get("witness_signature")
        if isinstance(mvar_signature, str) and mvar_signature:
            return mvar_signature

        if self._signing_mode == "ed25519" and self._ed25519_private_key is not None:
            payload = self._signature_payload(witness_id, request, decision)
            signature = self._ed25519_private_key.sign(payload)
            return f"ed25519:{signature.hex()}"

        # Compatibility fallback when cryptography is unavailable.
        fallback_payload = (
            f"{witness_id}:{request.request_id}:{decision.sink_type}:"
            f"{decision.decision}:{decision.reason_code}:{decision.policy_id}:{decision.engine}"
        )
        signature_hash = hashlib.sha256(fallback_payload.encode("utf-8")).hexdigest()[:16]
        return f"ed25519_stub:{signature_hash}"

    def _signature_payload(
        self, witness_id: str, request: ActionRequest, decision: ActionDecision
    ) -> bytes:
        payload = (
            f"{witness_id}:{request.request_id}:{decision.sink_type}:"
            f"{decision.decision}:{decision.reason_code}:{decision.policy_id}:{decision.engine}"
        )
        return payload.encode("utf-8")

    def _initialize_signer(self) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except Exception:
            self._signing_mode = "ed25519_stub"
            self._ed25519_private_key = None
            return

        key_path = self._resolve_key_path()
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if key_path.exists():
                key_bytes = key_path.read_bytes()
                self._ed25519_private_key = serialization.load_pem_private_key(
                    key_bytes,
                    password=None,
                )
            else:
                private_key = Ed25519PrivateKey.generate()
                pem_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                key_path.write_bytes(pem_bytes)
                try:
                    os.chmod(key_path, 0o600)
                except OSError:
                    pass
                self._ed25519_private_key = private_key
            self._signing_mode = "ed25519"
        except Exception:
            self._signing_mode = "ed25519_stub"
            self._ed25519_private_key = None

    def _resolve_key_path(self) -> Path:
        explicit = os.getenv("CLAWZERO_WITNESS_KEY_PATH")
        if explicit:
            return Path(explicit).expanduser().resolve()
        state_root = os.getenv("CLAWZERO_STATE_DIR")
        base = Path(state_root).expanduser().resolve() if state_root else (Path.home() / ".clawzero")
        return (base / "keys" / "witness_ed25519_private_key.pem").resolve()

    def _resolve_chain_state(self) -> tuple[int, str]:
        if self.output_dir is None:
            if self._last_chain_index <= 0:
                return 1, "genesis"
            return self._last_chain_index + 1, self._last_content_hash or "genesis"

        witnesses = sorted(self.output_dir.glob("witness_*.json"))
        if not witnesses:
            return 1, "genesis"

        last_witness = self._load_last_witness(witnesses[-1])
        if not isinstance(last_witness, dict):
            return 1, "genesis"

        try:
            last_index = int(last_witness.get("chain_index", len(witnesses)))
        except (TypeError, ValueError):
            last_index = len(witnesses)

        content_hash = str(last_witness.get("content_hash", "")).strip()
        if not content_hash.startswith("sha256:"):
            content_hash = self._sha256_prefix(self._canonical_json(last_witness))

        return last_index + 1, content_hash

    @staticmethod
    def _load_last_witness(path: Path) -> dict[str, Any] | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def _canonical_json(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _sha256_prefix(payload: str) -> str:
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def _content_hash(self, witness: dict[str, Any]) -> str:
        payload = dict(witness)
        payload.pop("content_hash", None)
        return self._sha256_prefix(self._canonical_json(payload))

    def _persist(self, witness: dict) -> None:
        if self.output_dir is None:
            return
        self._counter += 1
        filename = f"witness_{self._counter:03d}.json"
        filepath = self.output_dir / filename
        filepath.write_text(json.dumps(witness, indent=2), encoding="utf-8")

    def render_cli(self, witness: dict) -> str:
        lines = [
            "Execution Decision Witness",
            "-" * 40,
            f"schema    : {witness.get('schema_version', 'N/A')}",
            f"index     : {witness.get('chain_index', 'N/A')}",
            f"prev_hash : {witness.get('previous_hash', 'N/A')}",
            f"hash      : {witness.get('content_hash', 'N/A')}",
            f"sink      : {witness.get('sink_type', 'N/A')}",
            f"target    : {witness.get('target', 'N/A')}",
            f"decision  : {str(witness.get('decision', 'N/A')).upper()}",
            f"reason    : {witness.get('reason_code', 'N/A')}",
            f"policy_id : {witness.get('policy_id', 'N/A')}",
            f"engine    : {witness.get('engine', 'N/A')}",
            f"signature : {witness.get('witness_signature', 'N/A')}",
        ]
        return "\n".join(lines)


_global_witness_generator: Optional[WitnessGenerator] = None


def get_witness_generator() -> WitnessGenerator:
    global _global_witness_generator
    if _global_witness_generator is None:
        _global_witness_generator = WitnessGenerator()
    return _global_witness_generator


def set_witness_output_dir(output_dir: Path) -> None:
    global _global_witness_generator
    _global_witness_generator = WitnessGenerator(output_dir=output_dir)


def generate_witness(request: ActionRequest, decision: ActionDecision) -> dict:
    return get_witness_generator().generate(request, decision)
