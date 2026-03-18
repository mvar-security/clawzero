"""Phase B CLI coverage for package trust visibility in audit path."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero import cli
from clawzero.contracts import ActionDecision, ActionRequest


def test_audit_decision_displays_package_trust(monkeypatch, capsys) -> None:
    seen: dict[str, ActionRequest] = {}

    class FakeRuntime:
        def __init__(self, profile: str = "prod_locked", cec_enforce: bool = False):
            _ = profile, cec_enforce
            self.last_witness = {"witness_id": "witness-phaseb-cli"}

        def evaluate(self, request: ActionRequest) -> ActionDecision:
            seen["request"] = request
            return ActionDecision(
                request_id=request.request_id,
                decision="block",
                reason_code="UNSIGNED_MARKETPLACE_PACKAGE",
                human_reason="blocked",
                sink_type=request.sink_type,
                target=request.target,
                policy_profile=request.policy_profile,
                engine="mvar-security",
                policy_id="mvar-security.v1.4.3",
                annotations={
                    "package_trust": {
                        "package_source": request.package_source,
                        "publisher_id": request.publisher_id,
                        "policy_reason": "UNSIGNED_MARKETPLACE_PACKAGE",
                        "policy_decision": "block",
                    }
                },
            )

    monkeypatch.setattr(cli, "MVARRuntime", FakeRuntime)
    rc = cli.main(
        [
            "audit",
            "decision",
            "--profile",
            "prod_locked",
            "--sink-type",
            "tool.custom",
            "--target",
            "marketplace.skill.run",
            "--package-source",
            "clawhub",
            "--publisher-id",
            "unknown-publisher",
            "--package-hash",
            "sha256:deadbeef",
        ]
    )
    out = capsys.readouterr().out

    assert rc == 0
    assert "pkg_source : clawhub" in out
    assert "publisher  : unknown-publisher" in out
    assert "pkg_trust  : block (UNSIGNED_MARKETPLACE_PACKAGE)" in out

    request = seen["request"]
    assert request.package_source == "clawhub"
    assert request.publisher_id == "unknown-publisher"
    assert request.package_hash == "sha256:deadbeef"
