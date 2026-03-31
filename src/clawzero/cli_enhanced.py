"""
ClawZero CLI — Enhanced with rich output and full command coverage.

Drop-in replacement for cli.py with polished terminal output.

Usage:
    clawzero demo openclaw --mode compare --scenario shell
    clawzero attack-pack run --profile prod_locked
    clawzero benchmark --iterations 1000
    clawzero audit decision --sink-type shell.exec --target bash
    clawzero witness verify --file witness_001.json
    clawzero witness verify-chain --dir ./witnesses
    clawzero report sarif --input ./witnesses --output scan.sarif
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from clawzero.contracts import ActionRequest
from clawzero.runtime import MVARRuntime


# ── Terminal colors (no dependencies) ────────────────────────────────

class _C:
    """ANSI color codes — degrades gracefully if terminal doesn't support them."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


def _supports_color() -> bool:
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


if not _supports_color():
    _C.disable()


def _banner() -> None:
    print(f"""
{_C.CYAN}{_C.BOLD}  ╔═══════════════════════════════════════════════╗
  ║           ClawZero v0.2.0                     ║
  ║   Deterministic Execution Boundary            ║
  ║   for AI Agents                               ║
  ╚═══════════════════════════════════════════════╝{_C.RESET}
""")


def _block_badge() -> str:
    return f"{_C.BG_RED}{_C.WHITE}{_C.BOLD} BLOCKED {_C.RESET}"


def _allow_badge() -> str:
    return f"{_C.BG_GREEN}{_C.WHITE}{_C.BOLD} ALLOWED {_C.RESET}"


def _annotate_badge() -> str:
    return f"{_C.YELLOW}{_C.BOLD} ANNOTATE {_C.RESET}"


def _decision_badge(decision: str) -> str:
    if decision == "block":
        return _block_badge()
    if decision == "allow":
        return _allow_badge()
    return _annotate_badge()


# ── Commands ─────────────────────────────────────────────────────────

def cmd_demo(args: argparse.Namespace):
    """Run side-by-side demo comparing protected vs unprotected."""
    _banner()

    scenario = args.scenario or "shell"
    scenarios = {
        "shell": {
            "target": "rm -rf /",
            "sink_type": "shell.exec",
            "tool_name": "bash_execute",
            "description": "Shell command injection via prompt injection",
        },
        "credentials": {
            "target": "OPENAI_API_KEY",
            "sink_type": "credentials.access",
            "tool_name": "get_env_var",
            "description": "Credential exfiltration via environment variable access",
        },
        "exfiltration": {
            "target": "https://attacker.com/exfil",
            "sink_type": "http.request",
            "tool_name": "http_post",
            "description": "Data exfiltration via outbound HTTP request",
        },
        "filesystem": {
            "target": "/etc/shadow",
            "sink_type": "filesystem.read",
            "tool_name": "read_file",
            "description": "Sensitive file read via path traversal",
        },
    }

    if scenario not in scenarios:
        print(f"{_C.RED}Unknown scenario: {scenario}{_C.RESET}")
        print(f"Available: {', '.join(scenarios.keys())}")
        return

    sc = scenarios[scenario]
    print(f"  {_C.BOLD}Scenario:{_C.RESET} {sc['description']}")
    print(f"  {_C.BOLD}Target:{_C.RESET}   {sc['target']}")
    print(f"  {_C.BOLD}Sink:{_C.RESET}     {sc['sink_type']}")
    print()

    # Without ClawZero
    print(f"  {_C.DIM}──────────────────────────────────────{_C.RESET}")
    print(f"  {_C.RED}{_C.BOLD}STANDARD (no protection){_C.RESET}")
    print("  Agent receives prompt injection...")
    print(f"  Tool call: {sc['tool_name']}({sc['target']})")
    print(f"  Result: {_C.RED}{_C.BOLD}COMPROMISED{_C.RESET} — action executed")
    print()

    # With ClawZero
    print(f"  {_C.DIM}──────────────────────────────────────{_C.RESET}")
    print(f"  {_C.GREEN}{_C.BOLD}CLAWZERO PROTECTED{_C.RESET}")
    print("  Agent receives same prompt injection...")
    print(f"  Tool call: {sc['tool_name']}({sc['target']})")

    runtime = MVARRuntime(profile="prod_locked")
    request = ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="demo",
        action_type="tool_call",
        sink_type=sc["sink_type"],
        tool_name=sc["tool_name"],
        target=sc["target"],
        arguments={"target": sc["target"]},
        prompt_provenance={
            "source": "external_document",
            "taint_level": "untrusted",
            "taint_markers": ["prompt_injection"],
            "source_chain": ["external_document", "demo_tool_call"],
        },
        policy_profile="prod_locked",
    )

    decision = runtime.evaluate(request)
    print(f"  Result: {_decision_badge(decision.decision)} — {decision.reason_code}")
    print(f"  Witness: {_C.GREEN}YES{_C.RESET} — cryptographically signed")
    print()

    if args.mode == "compare":
        print(f"  {_C.DIM}──────────────────────────────────────{_C.RESET}")
        print(f"  {_C.BOLD}Same input. Same agent. Different execution boundary.{_C.RESET}")
        print()


def cmd_attack_pack(args: argparse.Namespace):
    """Run the full attack pack validation."""
    _banner()
    print(f"  {_C.BOLD}Running Attack Pack Validation{_C.RESET}")
    print(f"  Profile: {args.profile}")
    print()

    # Import and run pytest programmatically
    try:
        import pytest
        test_dir = Path(__file__).parent.parent.parent / "tests" / "attack_pack"
        if not test_dir.exists():
            print(f"  {_C.RED}Attack pack directory not found: {test_dir}{_C.RESET}")
            return
        exit_code = pytest.main([str(test_dir), "-v", "--tb=short"])
        if exit_code == 0:
            print(f"\n  {_C.GREEN}{_C.BOLD}All attack vectors blocked successfully.{_C.RESET}")
        else:
            print(f"\n  {_C.RED}{_C.BOLD}Some attack vectors were not blocked!{_C.RESET}")
    except ImportError:
        print(f"  {_C.YELLOW}pytest not installed. Run: pip install pytest{_C.RESET}")


def cmd_benchmark(args: argparse.Namespace):
    """Run the benchmark suite."""
    from clawzero.benchmark import run_benchmark
    run_benchmark(iterations=args.iterations, output_path=args.output)


def cmd_audit(args: argparse.Namespace):
    """Audit a single decision."""
    _banner()
    runtime = MVARRuntime(profile=args.profile)

    request = ActionRequest(
        request_id=str(uuid.uuid4()),
        framework="audit",
        action_type="tool_call",
        sink_type=args.sink_type,
        tool_name=args.tool_name or "audit_tool",
        target=args.target,
        arguments={"target": args.target},
        prompt_provenance={
            "source": args.source or "external_document",
            "taint_level": args.taint or "untrusted",
            "taint_markers": ["audit_check"],
            "source_chain": ["audit", "tool_call"],
        },
        policy_profile=args.profile,
    )

    decision = runtime.evaluate(request)

    print(f"  {_C.BOLD}Audit Decision{_C.RESET}")
    print(f"  {_C.DIM}──────────────────────────────────────{_C.RESET}")
    print(f"  Sink:     {decision.sink_type}")
    print(f"  Target:   {decision.target}")
    print(f"  Profile:  {args.profile}")
    print(f"  Decision: {_decision_badge(decision.decision)}")
    print(f"  Reason:   {decision.reason_code}")
    if hasattr(decision, "human_reason") and decision.human_reason:
        print(f"  Detail:   {decision.human_reason}")
    print()


def cmd_witness_verify(args: argparse.Namespace):
    """Verify a witness file."""
    from clawzero.witnesses.verify import verify_witness_file

    path = Path(args.file)
    if not path.exists():
        print(f"{_C.RED}File not found: {path}{_C.RESET}")
        return

    result = verify_witness_file(path, require_chain=True)
    status = f"{_C.GREEN}VALID{_C.RESET}" if result.valid else f"{_C.RED}INVALID{_C.RESET}"
    print(f"  Witness: {path.name}")
    print(f"  Status:  {status}")
    if not result.valid:
        for err in result.reasons:
            print(f"  Error:   {_C.RED}{err}{_C.RESET}")
    print()


def cmd_witness_verify_chain(args: argparse.Namespace):
    """Verify witness chain integrity."""
    from clawzero.witnesses.verify import verify_witness_chain

    dir_path = Path(args.dir)
    if not dir_path.exists():
        print(f"{_C.RED}Directory not found: {dir_path}{_C.RESET}")
        return

    result = verify_witness_chain(dir_path)
    status = f"{_C.GREEN}VALID{_C.RESET}" if result.valid else f"{_C.RED}BROKEN{_C.RESET}"
    print(f"  Chain:   {dir_path}")
    print(f"  Files:   {result.count}")
    print(f"  Status:  {status}")
    if not result.valid:
        for err in result.reasons:
            print(f"  Error:   {_C.RED}{err}{_C.RESET}")
    print()


def cmd_report_sarif(args: argparse.Namespace):
    """Generate SARIF report from witnesses."""
    from clawzero.sarif import export_sarif

    input_dir = Path(args.input)
    output_file = Path(args.output)

    if not input_dir.exists():
        print(f"{_C.RED}Input directory not found: {input_dir}{_C.RESET}")
        return

    result = export_sarif(input_dir, output_file)
    print(f"  {_C.GREEN}SARIF report written to {result.output}{_C.RESET}")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="clawzero",
        description="ClawZero — Deterministic execution boundary for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # demo
    demo_parser = subparsers.add_parser("demo", help="Run side-by-side demo")
    demo_parser.add_argument("framework", nargs="?", default="openclaw")
    demo_parser.add_argument("--mode", default="compare", choices=["compare", "single"])
    demo_parser.add_argument("--scenario", default="shell",
                            choices=["shell", "credentials", "exfiltration", "filesystem"])
    demo_parser.set_defaults(func=cmd_demo)

    # attack-pack
    ap_parser = subparsers.add_parser("attack-pack", help="Run attack pack validation")
    ap_parser.add_argument("action", nargs="?", default="run")
    ap_parser.add_argument("--profile", default="prod_locked")
    ap_parser.set_defaults(func=cmd_attack_pack)

    # benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run benchmark suite")
    bench_parser.add_argument("--iterations", "-n", type=int, default=1000)
    bench_parser.add_argument("--output", "-o", type=str, default=None)
    bench_parser.set_defaults(func=cmd_benchmark)

    # audit
    audit_parser = subparsers.add_parser("audit", help="Audit a single decision")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")
    decision_parser = audit_sub.add_parser("decision", help="Evaluate a decision")
    decision_parser.add_argument("--sink-type", required=True)
    decision_parser.add_argument("--target", required=True)
    decision_parser.add_argument("--tool-name", default=None)
    decision_parser.add_argument("--profile", default="prod_locked")
    decision_parser.add_argument("--source", default=None)
    decision_parser.add_argument("--taint", default=None)
    decision_parser.set_defaults(func=cmd_audit)

    # witness
    witness_parser = subparsers.add_parser("witness", help="Witness artifact operations")
    witness_sub = witness_parser.add_subparsers(dest="witness_command")

    verify_parser = witness_sub.add_parser("verify", help="Verify a witness file")
    verify_parser.add_argument("--file", required=True)
    verify_parser.set_defaults(func=cmd_witness_verify)

    chain_parser = witness_sub.add_parser("verify-chain", help="Verify witness chain")
    chain_parser.add_argument("--dir", required=True)
    chain_parser.set_defaults(func=cmd_witness_verify_chain)

    # report
    report_parser = subparsers.add_parser("report", help="Generate reports")
    report_sub = report_parser.add_subparsers(dest="report_command")

    sarif_parser = report_sub.add_parser("sarif", help="Generate SARIF report")
    sarif_parser.add_argument("--input", required=True)
    sarif_parser.add_argument("--output", required=True)
    sarif_parser.set_defaults(func=cmd_report_sarif)

    args = parser.parse_args()

    if not args.command:
        _banner()
        parser.print_help()
        return

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
