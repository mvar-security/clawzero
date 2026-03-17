"""Phase A control-plane hardening tests: websocket + network isolation."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime


def _runtime(
    tmp_path: Path,
    *,
    profile: str = "dev_balanced",
    network_mode: str = "unrestricted",
    network_allowlist: list[str] | None = None,
) -> MVARRuntime:
    witness_dir = tmp_path / f"witness_{uuid.uuid4().hex}"
    witness_dir.mkdir(parents=True, exist_ok=True)
    rt = MVARRuntime(
        profile=profile,
        witness_dir=witness_dir,
        network_mode=network_mode,
        network_allowlist=network_allowlist or [],
    )
    rt._mvar_available = False
    rt._mvar_governor = None
    rt.engine = "embedded-policy-v0.1"
    rt.policy_id = "mvar-embedded.v0.1"
    return rt


def _request(
    *,
    sink_type: str,
    target: str,
    source: str,
    taint_level: str,
    input_class: InputClass,
    arguments: dict[str, str] | None = None,
    policy_profile: str = "dev_balanced",
) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="phaseA_tool",
        target=target,
        arguments=arguments or {},
        input_class=input_class.value,
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "source_chain": [source, "tool_call"],
            "taint_markers": []
            if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
            else ["external_input"],
        },
        policy_profile=policy_profile,
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "event_intercept",
                "framework": "openclaw",
            }
        },
    )


def test_websocket_missing_auth_blocked(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, network_mode="unrestricted")
    decision = rt.evaluate(
        _request(
            sink_type="websocket.connect",
            target="ws://localhost:8765/control",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
            arguments={"origin": "http://localhost:3000"},
        )
    )
    assert decision.decision == "block"
    assert decision.reason_code == "MISSING_CONTROLPLANE_AUTH"


def test_websocket_untrusted_origin_blocked(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, network_mode="unrestricted")
    decision = rt.evaluate(
        _request(
            sink_type="websocket.connect",
            target="ws://localhost:8765/control",
            source="external_document",
            taint_level="untrusted",
            input_class=InputClass.UNTRUSTED,
            arguments={"origin": "https://attacker.example", "auth_token": "doctor-token"},
        )
    )
    assert decision.decision == "block"
    assert decision.reason_code == "UNTRUSTED_WEBSOCKET_ORIGIN"


def test_network_mode_localhost_only_blocks_external_http(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, network_mode="localhost_only")
    decision = rt.evaluate(
        _request(
            sink_type="http.request",
            target="https://example.com/api",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )
    assert decision.decision == "block"
    assert decision.reason_code == "NETWORK_ISOLATION_VIOLATION"


def test_network_mode_allowlist_only_allows_configured_host(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        network_mode="allowlist_only",
        network_allowlist=["api.company.com"],
    )
    decision = rt.evaluate(
        _request(
            sink_type="http.request",
            target="https://api.company.com/v1/health",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
        )
    )
    assert decision.decision == "allow"


def test_network_mode_allowlist_only_blocks_non_allowlisted_host(tmp_path: Path) -> None:
    rt = _runtime(
        tmp_path,
        network_mode="allowlist_only",
        network_allowlist=["api.company.com"],
    )
    decision = rt.evaluate(
        _request(
            sink_type="websocket.connect",
            target="wss://ops.attacker.example/control",
            source="user_request",
            taint_level="trusted",
            input_class=InputClass.TRUSTED,
            arguments={"origin": "https://api.company.com", "auth_token": "tkn"},
        )
    )
    assert decision.decision == "block"
    assert decision.reason_code == "NETWORK_ISOLATION_VIOLATION"
