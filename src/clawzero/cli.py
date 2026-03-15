"""ClawZero command line interface.

ClawZero is an in-path enforcement substrate for production agent flows.
The CLI exposes enforcement-first jobs: demo proof, witness inspection,
policy audit, and attack replay.
"""

from __future__ import annotations

import argparse
import json
import runpy
import sys
import uuid
from pathlib import Path

from clawzero.contracts import ActionRequest
from clawzero.runtime import MVARRuntime
from clawzero.witnesses.verify import verify_witness_chain, verify_witness_file


def _run_openclaw_demo(mode: str, scenario: str, output_dir: str | None = None) -> int:
    original_argv = sys.argv[:]
    try:
        sys.argv = [
            "clawzero demo openclaw",
            "--mode",
            mode,
            "--scenario",
            scenario,
        ]
        if output_dir:
            sys.argv.extend(["--output-dir", output_dir])
        runpy.run_module("clawzero.demo.openclaw_attack_demo", run_name="__main__")
        return 0
    except ModuleNotFoundError:
        print(
            "Demo module not found: clawzero.demo.openclaw_attack_demo",
            file=sys.stderr,
        )
        return 2
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 1
    finally:
        sys.argv = original_argv


def _cmd_demo_openclaw(args: argparse.Namespace) -> int:
    return _run_openclaw_demo(mode=args.mode, scenario=args.scenario, output_dir=args.output_dir)


def _cmd_attack_replay(args: argparse.Namespace) -> int:
    # Attack replay is intentionally routed through the same enforcement demo.
    return _run_openclaw_demo(mode="compare", scenario=args.scenario, output_dir=getattr(args, "output_dir", None))


def _cmd_audit_decision(args: argparse.Namespace) -> int:
    runtime = MVARRuntime(profile=args.profile)

    taint_markers = [m.strip() for m in args.taint_markers.split(",") if m.strip()]
    request = ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="openclaw",
        action_type="tool_call",
        sink_type=args.sink_type,
        tool_name=args.tool_name,
        target=args.target,
        arguments={"command": args.command},
        prompt_provenance={
            "source": args.source,
            "taint_level": args.taint_level,
            "source_chain": [args.source, "openclaw_tool_call"],
            "taint_markers": taint_markers,
        },
        policy_profile=args.profile,
        metadata={
            "adapter": {
                "name": "openclaw",
                "mode": "tool_wrap",
                "framework": "openclaw",
            }
        },
    )

    decision = runtime.evaluate(request)

    print("ClawZero Enforcement Audit")
    print("-" * 32)
    print(f"decision   : {decision.decision}")
    print(f"reason     : {decision.reason_code}")
    print(f"human      : {decision.human_reason}")
    print(f"sink       : {decision.sink_type}")
    print(f"target     : {decision.target}")
    print(f"policy_id  : {decision.policy_id}")
    print(f"engine     : {decision.engine}")
    if runtime.last_witness:
        print(f"witness_id : {runtime.last_witness.get('witness_id')}")
    return 0


def _cmd_witness_show(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"Witness file not found: {path}", file=sys.stderr)
        return 2

    witness = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(witness, indent=2))
    return 0


def _cmd_witness_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"Witness file not found: {path}", file=sys.stderr)
        return 2

    result = verify_witness_file(path, require_chain=True)
    if not result.valid:
        print(f"INVALID: {'; '.join(result.reasons)}")
        return 1

    print("VALID")
    return 0


def _cmd_witness_verify_chain(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    if not directory.exists() or not directory.is_dir():
        print(f"Witness directory not found: {directory}", file=sys.stderr)
        return 2

    result = verify_witness_chain(directory)
    if not result.valid:
        if result.broken_index is not None:
            print(f"CHAIN BROKEN at index {result.broken_index}: {'; '.join(result.reasons)}")
        else:
            print(f"CHAIN BROKEN: {'; '.join(result.reasons)}")
        return 1

    print(f"CHAIN VALID ({result.count} witnesses)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawzero",
        description=(
            "ClawZero: deterministic in-path execution boundary for OpenClaw agent flows."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser(
        "demo",
        help="Run enforcement proof demos (same input, different boundary).",
    )
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    demo_openclaw = demo_sub.add_parser(
        "openclaw",
        help="Run OpenClaw demo through standard vs MVAR-protected paths.",
    )
    demo_openclaw.add_argument("--mode", choices=["standard", "mvar", "compare"], default="compare")
    demo_openclaw.add_argument(
        "--scenario", choices=["shell", "credentials", "benign"], default="shell"
    )
    demo_openclaw.add_argument(
        "--output-dir",
        default=None,
        help="Optional directory for canonical witness outputs (witness_*.json).",
    )
    demo_openclaw.set_defaults(func=_cmd_demo_openclaw)

    witness = subparsers.add_parser(
        "witness",
        help="Inspect and validate signed witness artifacts from enforcement decisions.",
    )
    witness_sub = witness.add_subparsers(dest="witness_command", required=True)
    witness_show = witness_sub.add_parser("show", help="Print a witness JSON artifact.")
    witness_show.add_argument("--file", required=True, help="Path to witness JSON file.")
    witness_show.set_defaults(func=_cmd_witness_show)

    witness_verify = witness_sub.add_parser(
        "verify", help="Verify required canonical fields in a witness artifact."
    )
    witness_verify.add_argument("--file", required=True, help="Path to witness JSON file.")
    witness_verify.set_defaults(func=_cmd_witness_verify)

    witness_verify_chain = witness_sub.add_parser(
        "verify-chain", help="Verify sequential hash-chain integrity for witness directory."
    )
    witness_verify_chain.add_argument("--dir", required=True, help="Directory containing witness JSON files.")
    witness_verify_chain.set_defaults(func=_cmd_witness_verify_chain)

    audit = subparsers.add_parser(
        "audit",
        help="Audit deterministic policy enforcement for a specific sink request.",
    )
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_decision = audit_sub.add_parser(
        "decision", help="Evaluate a single request through the active MVAR runtime."
    )
    audit_decision.add_argument("--profile", default="prod_locked")
    audit_decision.add_argument("--sink-type", required=True)
    audit_decision.add_argument("--target", required=True)
    audit_decision.add_argument("--tool-name", default="tool_call")
    audit_decision.add_argument("--command", default="")
    audit_decision.add_argument("--source", default="external_document")
    audit_decision.add_argument("--taint-level", default="untrusted")
    audit_decision.add_argument("--taint-markers", default="prompt_injection,external_content")
    audit_decision.set_defaults(func=_cmd_audit_decision)

    attack = subparsers.add_parser(
        "attack",
        help="Replay known attack scenarios to prove sink-boundary enforcement.",
    )
    attack_sub = attack.add_subparsers(dest="attack_command", required=True)
    attack_replay = attack_sub.add_parser(
        "replay",
        help="Run compare-mode attack replay (standard compromised vs MVAR blocked).",
    )
    attack_replay.add_argument(
        "--scenario", choices=["shell", "credentials", "benign"], default="shell"
    )
    attack_replay.set_defaults(func=_cmd_attack_replay)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
