"""Witness validation and chain verification utilities."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


WITNESS_REQUIRED_FIELDS = {
    "timestamp",
    "agent_runtime",
    "sink_type",
    "target",
    "decision",
    "reason_code",
    "policy_id",
    "engine",
    "provenance",
    "adapter",
    "witness_signature",
}

WITNESS_CHAIN_FIELDS = {
    "schema_version",
    "chain_index",
    "previous_hash",
    "content_hash",
}


@dataclass
class VerificationResult:
    valid: bool
    reasons: list[str]


@dataclass
class ChainVerificationResult:
    valid: bool
    reasons: list[str]
    count: int
    broken_index: int | None = None


def verify_witness_file(path: Path, *, require_chain: bool = True) -> VerificationResult:
    try:
        witness = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return VerificationResult(valid=False, reasons=[f"parse error: {exc}"])

    return verify_witness_object(witness, require_chain=require_chain)


def verify_witness_object(witness: dict[str, Any], *, require_chain: bool = True) -> VerificationResult:
    reasons: list[str] = []

    missing = sorted(WITNESS_REQUIRED_FIELDS.difference(witness.keys()))
    if missing:
        reasons.append(f"missing fields: {', '.join(missing)}")

    signature_reason = _validate_signature(witness)
    if signature_reason:
        reasons.append(signature_reason)

    if require_chain:
        missing_chain = sorted(WITNESS_CHAIN_FIELDS.difference(witness.keys()))
        if missing_chain:
            reasons.append(f"missing chain fields: {', '.join(missing_chain)}")
        else:
            chain_reason = _validate_chain_fields(witness)
            if chain_reason:
                reasons.append(chain_reason)

    return VerificationResult(valid=not reasons, reasons=reasons)


def verify_witness_chain(directory: Path) -> ChainVerificationResult:
    files = sorted(directory.glob("*.json"))
    if not files:
        return ChainVerificationResult(valid=False, reasons=["no witness files found"], count=0)

    parsed: list[tuple[int, dict[str, Any], Path]] = []
    for file in files:
        try:
            witness = json.loads(file.read_text(encoding="utf-8"))
            idx = int(witness["chain_index"])
        except Exception as exc:
            return ChainVerificationResult(valid=False, reasons=[f"invalid chain_index: {exc}"], count=0)
        verify = verify_witness_object(witness, require_chain=True)
        if not verify.valid:
            return ChainVerificationResult(
                valid=False,
                reasons=verify.reasons,
                count=len(parsed),
                broken_index=idx,
            )
        parsed.append((idx, witness, file))

    parsed.sort(key=lambda item: item[0])

    expected_index = 1
    prev_content_hash = "genesis"
    for idx, witness, _ in parsed:
        if idx != expected_index:
            return ChainVerificationResult(
                valid=False,
                reasons=[f"gap or duplicate at index {idx}, expected {expected_index}"],
                count=len(parsed),
                broken_index=idx,
            )
        previous_hash = str(witness.get("previous_hash", ""))
        if previous_hash != prev_content_hash:
            return ChainVerificationResult(
                valid=False,
                reasons=[f"previous_hash mismatch at index {idx}"],
                count=len(parsed),
                broken_index=idx,
            )
        prev_content_hash = str(witness.get("content_hash", ""))
        expected_index += 1

    return ChainVerificationResult(valid=True, reasons=[], count=len(parsed))


def _validate_signature(witness: dict[str, Any]) -> str | None:
    signature = str(witness.get("witness_signature", "")).strip()
    if not signature:
        return "missing witness_signature"

    if signature.startswith("ed25519:"):
        sig_hex = signature.split(":", 1)[1]
        try:
            raw = bytes.fromhex(sig_hex)
        except ValueError:
            return "invalid ed25519 hex encoding"
        if len(raw) != 64:
            return "invalid ed25519 signature length"
        return None

    if signature.startswith("ed25519_stub:"):
        stub = signature.split(":", 1)[1]
        try:
            raw = bytes.fromhex(stub)
        except ValueError:
            return "invalid ed25519_stub hex encoding"
        if len(raw) != 8:
            return "invalid ed25519_stub length"
        return None

    return "unsupported signature format"


def _validate_chain_fields(witness: dict[str, Any]) -> str | None:
    schema = str(witness.get("schema_version", ""))
    if schema != "1.1":
        return "unsupported schema_version"

    try:
        index = int(witness.get("chain_index"))
    except (TypeError, ValueError):
        return "chain_index is not an integer"
    if index < 1:
        return "chain_index must be >= 1"

    previous_hash = str(witness.get("previous_hash", "")).strip()
    if index == 1:
        if previous_hash != "genesis":
            return "index 1 must use previous_hash=genesis"
    elif not previous_hash.startswith("sha256:"):
        return "previous_hash must use sha256: prefix"

    content_hash = str(witness.get("content_hash", "")).strip()
    if not content_hash.startswith("sha256:"):
        return "content_hash must use sha256: prefix"

    expected = _content_hash(witness)
    if content_hash != expected:
        return "content_hash mismatch"
    return None


def _content_hash(witness: dict[str, Any]) -> str:
    payload = dict(witness)
    payload.pop("content_hash", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
