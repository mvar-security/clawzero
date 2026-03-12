#!/usr/bin/env python3
# Powered by MVAR (MIRRA Verified Agent Runtime)
# github.com/mvar-security/mvar
"""OpenClaw integration example for ClawZero."""

import os
import sys
from pathlib import Path

# Add parent directory to path for local development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawzero import set_witness_output_dir
from clawzero.adapters import OpenClawAdapter
from clawzero.exceptions import ExecutionBlocked

WITNESS_DIR = Path(__file__).parent / "witness_output"
WITNESS_DIR.mkdir(exist_ok=True)
set_witness_output_dir(WITNESS_DIR)


# ============================================================================
# Simulated OpenClaw Tools
# ============================================================================

def bash_execute(command: str) -> str:
    """Simulated bash execution tool (OpenClaw)."""
    import subprocess

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=2
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def file_read(path: str) -> str:
    """Simulated file read tool (OpenClaw)."""
    try:
        with open(path) as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


def http_get(url: str) -> str:
    """Simulated HTTP GET tool (OpenClaw)."""
    return f"Simulated GET {url}"


# ============================================================================
# Demo: Wrap Tools with ClawZero
# ============================================================================

def demo_wrap_tools() -> None:
    """Demonstrate wrapping OpenClaw tools with ClawZero."""
    print("=" * 60)
    print("OpenClaw + ClawZero Integration Demo")
    print("=" * 60)
    print()

    adapter = OpenClawAdapter(
        profile="prod_locked",
        agent_id="demo_agent",
        session_id="demo_session_001",
    )

    safe_bash = adapter.wrap_tool(bash_execute, sink_type="shell.exec")
    safe_file_read = adapter.wrap_tool(file_read, sink_type="filesystem.read")
    safe_http_get = adapter.wrap_tool(http_get, sink_type="http.request")

    print("✓ Tools wrapped with ClawZero protection")
    print()

    print("Test 1: Shell execution (should be BLOCKED)")
    try:
        safe_bash("whoami")
        print("  Result: EXECUTED ✗ (unexpected)")
    except ExecutionBlocked as e:
        print("  Result: BLOCKED ✓")
        print(f"  Reason: {e}")
    print()

    print("Test 2: Read /etc/passwd (should be BLOCKED)")
    try:
        safe_file_read("/etc/passwd")
        print("  Result: EXECUTED ✗ (unexpected)")
    except ExecutionBlocked as e:
        print("  Result: BLOCKED ✓")
        print(f"  Reason: {e}")
    print()

    print("Test 3: HTTP to external domain (should be BLOCKED)")
    try:
        safe_http_get("https://attacker.com")
        print("  Result: EXECUTED ✗ (unexpected)")
    except ExecutionBlocked as e:
        print("  Result: BLOCKED ✓")
        print(f"  Reason: {e}")
    print()

    print("Test 4: HTTP to localhost (should be ALLOWED)")
    try:
        result = safe_http_get("http://localhost:8080/api")
        print("  Result: ALLOWED ✓")
        print(f"  Output: {result}")
    except ExecutionBlocked as e:
        print("  Result: BLOCKED ✗ (unexpected)")
        print(f"  Reason: {e}")
    print()

    print("=" * 60)
    print("Integration demo complete")
    print("=" * 60)


# ============================================================================
# Demo: Event-Level Interception
# ============================================================================

def demo_event_interception() -> None:
    """Demonstrate event-level interception."""
    print()
    print("=" * 60)
    print("Event-Level Interception Demo")
    print("=" * 60)
    print()

    adapter = OpenClawAdapter(profile="prod_locked")

    events = [
        {
            "tool_name": "bash_execute",
            "arguments": {"command": "rm -rf /tmp/test"},
            "context": {"user_message": "clean up files"},
        },
        {
            "tool_name": "file_read",
            "arguments": {"path": "/etc/shadow"},
            "context": {"user_message": "show me system info"},
        },
        {
            "tool_name": "http_get",
            "arguments": {"url": "http://localhost:8080/status"},
            "context": {"user_message": "check server status"},
        },
    ]

    for i, event in enumerate(events, 1):
        print(f"Event {i}: {event['tool_name']}")
        try:
            adapter.intercept_tool_call(event)
            print("  Result: ALLOWED ✓")
        except ExecutionBlocked as e:
            print("  Result: BLOCKED ✓")
            print(f"  Reason: {e}")
        print()

    print("=" * 60)
    print("Event interception demo complete")
    print("=" * 60)


def main() -> None:
    """Run all demos."""
    demo_wrap_tools()
    demo_event_interception()


if __name__ == "__main__":
    main()
