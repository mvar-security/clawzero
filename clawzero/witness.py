"""
ClawZero witness generation.

Every enforcement decision emits a signed witness artifact.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from clawzero.contracts import ActionDecision, ActionRequest


class WitnessGenerator:
    """Generates canonical witness artifacts."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def generate(self, request: ActionRequest, decision: ActionDecision) -> dict:
        witness_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        source_chain = self._extract_source_chain(request)
        taint_markers = self._extract_taint_markers(request, decision)

        adapter_metadata = request.metadata.get(
            "adapter",
            {
                "name": request.framework,
                "mode": "tool_wrap",
                "framework": request.framework,
            },
        )

        witness = {
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

        decision.witness_id = witness_id

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

    def _sign(
        self, witness_id: str, request: ActionRequest, decision: ActionDecision
    ) -> str:
        payload = (
            f"{witness_id}:{request.request_id}:{decision.sink_type}:"
            f"{decision.decision}:{decision.reason_code}:{decision.policy_id}:{decision.engine}"
        )
        signature_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return f"ed25519_stub:{signature_hash}"

    def _persist(self, witness: dict) -> None:
        self._counter += 1
        filename = f"witness_{self._counter:03d}.json"
        filepath = self.output_dir / filename
        filepath.write_text(json.dumps(witness, indent=2), encoding="utf-8")

    def render_cli(self, witness: dict) -> str:
        lines = [
            "Execution Decision Witness",
            "-" * 40,
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
