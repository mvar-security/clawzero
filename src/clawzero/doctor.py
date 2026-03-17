"""OpenClaw doctor checks for launch-time environment validation."""

from __future__ import annotations

import logging
import re
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
import io
from pathlib import Path

from clawzero.contracts import ActionRequest, InputClass
from clawzero.runtime import MVARRuntime
from clawzero.witnesses.verify import verify_witness_chain, verify_witness_file

MIN_MVAR_VERSION = "1.4.3"


@dataclass
class DoctorCheck:
    name: str
    status: str
    detail: str


@dataclass
class DoctorReport:
    runtime: DoctorCheck
    witness: DoctorCheck
    demo: DoctorCheck
    exposure: DoctorCheck | None = None
    witness_signer: str = "unknown"
    ledger_signer: str = "unknown"
    ledger_signer_detail: str | None = None

    @property
    def secure(self) -> bool:
        checks = [self.runtime, self.witness, self.demo]
        if self.exposure is not None:
            checks.append(self.exposure)
        return all(check.status == "OK" for check in checks)

    @property
    def status(self) -> str:
        return "SECURE" if self.secure else "WARNINGS (see above)"


def _parse_version(raw_version: str) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", raw_version)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _runtime_check(minimum_version: str = MIN_MVAR_VERSION) -> DoctorCheck:
    try:
        installed_version = version("mvar-security")
    except PackageNotFoundError:
        return DoctorCheck("Runtime", "WARN", "mvar-security missing")

    parsed_installed = _parse_version(installed_version)
    parsed_minimum = _parse_version(minimum_version)
    if parsed_installed is None or parsed_minimum is None:
        return DoctorCheck("Runtime", "WARN", f"unparseable version '{installed_version}'")

    if parsed_installed < parsed_minimum:
        return DoctorCheck(
            "Runtime",
            "WARN",
            f"mvar-security {installed_version} below {minimum_version}",
        )

    try:
        captured = io.StringIO()
        with redirect_stdout(captured), redirect_stderr(captured):
            from mvar.governor import ExecutionGovernor

        _ = ExecutionGovernor
    except Exception:
        return DoctorCheck("Runtime", "WARN", "ExecutionGovernor import failed")

    return DoctorCheck("Runtime", "OK", f"mvar-security {installed_version}")




@contextmanager
def _with_quiet_runtime_logs() -> Iterator[None]:
    runtime_logger = logging.getLogger("clawzero.runtime.engine")
    previous_level = runtime_logger.level
    runtime_logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        runtime_logger.setLevel(previous_level)


def _sample_request(*, sink_type: str, target: str, input_class: InputClass, source: str) -> ActionRequest:
    taint_level = "trusted" if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED} else "untrusted"
    return ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        agent_id="doctor_agent",
        session_id="doctor_session",
        action_type="tool_call",
        sink_type=sink_type,
        tool_name="doctor_tool",
        target=target,
        arguments={"target": target},
        input_class=input_class.value,
        prompt_provenance={
            "source": source,
            "taint_level": taint_level,
            "source_chain": [source, "doctor_check", "tool_call"],
            "taint_markers": []
            if input_class in {InputClass.TRUSTED, InputClass.PRE_AUTHORIZED}
            else ["external_content"],
        },
        policy_profile="prod_locked",
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "doctor_check",
                "framework": "openclaw",
            }
        },
    )


def _exposure_check() -> DoctorCheck:
    with _with_quiet_runtime_logs():
        runtime = MVARRuntime(profile="dev_balanced", network_mode="localhost_only")

    runtime._mvar_available = False
    runtime._mvar_governor = None
    runtime.engine = "embedded-policy-v0.1"
    runtime.policy_id = "mvar-embedded.v0.1"

    missing_auth = runtime.evaluate(
        ActionRequest(
            request_id=str(uuid.uuid4()),
            framework="openclaw",
            action_type="tool_call",
            sink_type="websocket.connect",
            tool_name="doctor_ws",
            target="ws://localhost:8765/control",
            arguments={"origin": "http://localhost:3000"},
            input_class=InputClass.TRUSTED.value,
            prompt_provenance={
                "source": "user_request",
                "taint_level": "trusted",
                "source_chain": ["user_request", "doctor_check", "tool_call"],
                "taint_markers": [],
            },
            policy_profile="dev_balanced",
            metadata={},
        )
    )
    if not (
        missing_auth.decision == "block"
        and missing_auth.reason_code == "MISSING_CONTROLPLANE_AUTH"
    ):
        return DoctorCheck("Exposure", "WARN", "websocket auth guard not enforced")

    untrusted_origin = runtime.evaluate(
        ActionRequest(
            request_id=str(uuid.uuid4()),
            framework="openclaw",
            action_type="tool_call",
            sink_type="websocket.connect",
            tool_name="doctor_ws",
            target="ws://localhost:8765/control",
            arguments={"origin": "https://attacker.example", "auth_token": "doctor-token"},
            input_class=InputClass.UNTRUSTED.value,
            prompt_provenance={
                "source": "external_document",
                "taint_level": "untrusted",
                "source_chain": ["external_document", "doctor_check", "tool_call"],
                "taint_markers": ["external_content"],
            },
            policy_profile="dev_balanced",
            metadata={},
        )
    )
    if not (
        untrusted_origin.decision == "block"
        and untrusted_origin.reason_code == "UNTRUSTED_WEBSOCKET_ORIGIN"
    ):
        return DoctorCheck("Exposure", "WARN", "websocket origin guard not enforced")

    return DoctorCheck("Exposure", "OK", "control-plane guards active")


def _witness_check(witness_dir: Path) -> DoctorCheck:
    witness_dir.mkdir(parents=True, exist_ok=True)
    with _with_quiet_runtime_logs():
        runtime = MVARRuntime(profile="prod_locked", witness_dir=witness_dir)
    runtime.evaluate(
        _sample_request(
            sink_type="tool.custom",
            target="doctor.sample",
            input_class=InputClass.TRUSTED,
            source="user_request",
        )
    )

    witness_files = sorted(witness_dir.glob("witness_*.json"))
    if not witness_files:
        return DoctorCheck("Witness", "INVALID", "sample witness not emitted")

    witness_result = verify_witness_file(witness_files[-1], require_chain=True)
    if not witness_result.valid:
        return DoctorCheck("Witness", "INVALID", "; ".join(witness_result.reasons))

    chain_result = verify_witness_chain(witness_dir)
    if not chain_result.valid:
        return DoctorCheck("Witness", "INVALID", "; ".join(chain_result.reasons))

    return DoctorCheck("Witness", "OK", "chain valid")


def _demo_check(demo_dir: Path) -> DoctorCheck:
    demo_dir.mkdir(parents=True, exist_ok=True)
    with _with_quiet_runtime_logs():
        runtime = MVARRuntime(profile="prod_locked", witness_dir=demo_dir)
    request = _sample_request(
        sink_type="shell.exec",
        target="bash",
        input_class=InputClass.UNTRUSTED,
        source="external_document",
    )
    decision = runtime.evaluate(request)

    if runtime.engine != "mvar-security":
        return DoctorCheck("Demo", "WARN", "embedded fallback")

    if decision.decision != "block":
        return DoctorCheck("Demo", "WARN", f"expected block, got {decision.decision}")

    return DoctorCheck("Demo", "OK", "attack blocked")


def run_openclaw_doctor(work_dir: Path | None = None) -> DoctorReport:
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="clawzero_doctor_"))
    work_dir.mkdir(parents=True, exist_ok=True)

    runtime = _runtime_check()
    with _with_quiet_runtime_logs():
        runtime_probe = MVARRuntime(profile="prod_locked")
    signer_info = runtime_probe.signer_info()
    witness = _witness_check(work_dir / "witness_check")
    demo = _demo_check(work_dir / "demo_check")
    exposure = _exposure_check()
    return DoctorReport(
        runtime=runtime,
        witness=witness,
        demo=demo,
        exposure=exposure,
        witness_signer=str(signer_info["witness_signer"]),
        ledger_signer=str(signer_info["ledger_signer"]),
        ledger_signer_detail=(
            str(signer_info["ledger_signer_detail"])
            if signer_info["ledger_signer_detail"] is not None
            else None
        ),
    )


def _format_line(check: DoctorCheck) -> str:
    dots = "." * max(1, 16 - len(check.name))
    return f"{check.name}{dots} {check.status} ({check.detail})"


def format_openclaw_doctor(report: DoctorReport) -> str:
    lines = [
        "clawzero doctor openclaw",
        "",
        _format_line(report.runtime),
        _format_line(report.witness),
        _format_line(report.demo),
        *([_format_line(report.exposure)] if report.exposure else []),
        "",
        f"Witness signer:  {report.witness_signer}",
        f"Ledger signer:   {report.ledger_signer}",
        *( [f"  {report.ledger_signer_detail}"] if report.ledger_signer_detail else [] ),
        "",
        f"Status: {report.status}",
    ]
    return "\n".join(lines)
