"""
ClawGuard Witness Generation

Every enforcement decision emits a cryptographically-signed witness.
Witnesses provide tamper-evident audit trails for compliance and debugging.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from clawguard.contracts import ActionDecision, ActionRequest


class WitnessGenerator:
    """
    Generates signed witnesses for ClawGuard enforcement decisions.

    Witnesses are structured JSON documents that prove:
    1. What action was requested
    2. What decision was made
    3. Why the decision was made
    4. When the decision occurred
    5. Cryptographic signature (stub in v0.1)
    """

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize witness generator.

        Args:
            output_dir: Directory to write witness files. If None, witnesses
                        are only returned in-memory (not persisted).
        """
        self.output_dir = output_dir
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self, request: ActionRequest, decision: ActionDecision
    ) -> dict:
        """
        Generate a signed witness for an enforcement decision.

        Args:
            request: The original action request
            decision: The enforcement decision made by ClawGuard

        Returns:
            Witness document as a dictionary
        """
        witness_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build provenance chain
        provenance = {
            "input_trust": decision.trust_level or "unknown",
            "source_chain": self._extract_source_chain(request),
            "taint_markers": decision.annotations.get("taint_markers", []),
        }

        # Construct witness document
        witness = {
            "witness_id": witness_id,
            "witness_version": "1.0",
            "timestamp": timestamp,
            "request_id": request.request_id,
            "framework": request.framework,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
            "action": {
                "type": request.action_type,
                "sink_type": request.sink_type,
                "tool_name": request.tool_name,
                "target": request.target,
                "arguments": request.arguments,
            },
            "decision": {
                "result": decision.decision,
                "reason_code": decision.reason_code,
                "human_reason": decision.human_reason,
                "policy_profile": decision.policy_profile,
            },
            "provenance": provenance,
            "annotations": decision.annotations,
            "witness_signature": self._sign(witness_id, request, decision),
        }

        # Update decision with witness_id
        decision.witness_id = witness_id

        # Persist if output_dir configured
        if self.output_dir:
            self._persist(witness)

        return witness

    def _extract_source_chain(self, request: ActionRequest) -> list[str]:
        """
        Extract provenance source chain from request.

        Examples:
        - ['user_prompt', 'tool_selection', 'tool_call']
        - ['system_directive', 'autonomous_action']
        - ['external_api', 'parsed_response', 'tool_call']
        """
        # In v0.1, use prompt_provenance if available, otherwise default
        if "source_chain" in request.prompt_provenance:
            return request.prompt_provenance["source_chain"]

        # Default chain based on action type
        if request.action_type == "tool_call":
            return ["user_prompt", "tool_selection", "tool_call"]
        else:
            return ["unknown_source", request.action_type]

    def _sign(
        self, witness_id: str, request: ActionRequest, decision: ActionDecision
    ) -> str:
        """
        Generate cryptographic signature for witness.

        V0.1: Stub implementation using SHA-256 hash.
        Future: Ed25519 signing with private key.

        Args:
            witness_id: UUID of the witness
            request: The action request
            decision: The enforcement decision

        Returns:
            Signature string (format: algorithm:signature)
        """
        # Construct signing payload
        payload = f"{witness_id}:{request.request_id}:{decision.decision}:{decision.reason_code}"

        # V0.1: Hash-based stub signature
        signature_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

        return f"sha256_stub:{signature_hash}"

    def _persist(self, witness: dict) -> None:
        """
        Persist witness to output directory.

        Filename format: witness_{witness_id}.json
        """
        filename = f"witness_{witness['witness_id']}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            json.dump(witness, f, indent=2)

    def render_cli(self, witness: dict) -> str:
        """
        Render witness as pretty CLI output.

        Args:
            witness: Witness document

        Returns:
            Formatted string for terminal display
        """
        action = witness["action"]
        decision = witness["decision"]
        provenance = witness["provenance"]

        lines = [
            "Execution Decision Witness",
            "─" * 40,
            f"action : {action['sink_type']}",
            f"target : {action.get('target', 'N/A')}",
            "",
            f"decision : {decision['result'].upper()}",
            f"reason   : {decision['human_reason']}",
            f"policy   : {decision['policy_profile']}",
            f"provenance: {' → '.join(provenance['source_chain'])}",
            f"signature: {witness['witness_signature']}",
        ]

        return "\n".join(lines)


# Global witness generator instance
_global_witness_generator: Optional[WitnessGenerator] = None


def get_witness_generator() -> WitnessGenerator:
    """Get or create the global witness generator instance"""
    global _global_witness_generator
    if _global_witness_generator is None:
        _global_witness_generator = WitnessGenerator()
    return _global_witness_generator


def set_witness_output_dir(output_dir: Path) -> None:
    """
    Configure witness output directory.

    Args:
        output_dir: Path where witness JSON files should be written
    """
    global _global_witness_generator
    _global_witness_generator = WitnessGenerator(output_dir=output_dir)


def generate_witness(
    request: ActionRequest, decision: ActionDecision
) -> dict:
    """
    Generate a witness for an enforcement decision.

    Args:
        request: The action request
        decision: The enforcement decision

    Returns:
        Witness document
    """
    return get_witness_generator().generate(request, decision)
