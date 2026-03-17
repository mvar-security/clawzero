"""OpenClaw doctor checks for launch-time environment validation."""

from __future__ import annotations

import logging
import re
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
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

    @property
    def secure(self) -> bool:
        return all(check.status == "OK" for check in (self.runtime, self.witness, self.demo))

    @property
    def status(self) -> str:
        return "SECURE" if self.secure else "WARNINGS (see above)"


def _parse_version(raw_version: str) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", raw_version)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


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
    witness = _witness_check(work_dir / "witness_check")
    demo = _demo_check(work_dir / "demo_check")
    return DoctorReport(runtime=runtime, witness=witness, demo=demo)


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
        "",
        f"Status: {report.status}",
    ]
    return "\n".join(lines)
