"""SARIF export tests for ClawZero witness artifacts."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from clawzero.contracts import ActionRequest
from clawzero.runtime import MVARRuntime
from clawzero.sarif import export_sarif, validate_sarif_report


def _request(sink_type: str, target: str, source: str, taint_level: str) -> ActionRequest:
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="test_tool",
        target=target,
        arguments={"target": target},
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "source_chain": [source, "tool_call"],
            "taint_markers": [] if taint_level == "trusted" else ["external_content"],
        },
        policy_profile="prod_locked",
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "event_intercept",
                "framework": "openclaw",
            }
        },
    )


def test_sarif_export_validates(tmp_path: Path):
    witness_dir = tmp_path / "witnesses"
    witness_dir.mkdir(parents=True, exist_ok=True)

    runtime = MVARRuntime(profile="prod_locked", witness_dir=witness_dir)
    runtime.evaluate(
        _request(
            sink_type="shell.exec",
            target="bash",
            source="external_document",
            taint_level="untrusted",
        )
    )
    runtime.evaluate(
        _request(
            sink_type="http.request",
            target="http://localhost:8080/api",
            source="user_request",
            taint_level="trusted",
        )
    )

    output = tmp_path / "results.sarif"
    result = export_sarif(input_dir=witness_dir, output_file=output)

    assert result.witness_count == 2
    assert result.result_count == 2
    assert output.exists()

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert validate_sarif_report(payload) == []

    levels = [item["level"] for item in payload["runs"][0]["results"]]
    assert "error" in levels
    assert "note" in levels

