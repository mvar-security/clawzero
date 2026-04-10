# ClawZero

![PyPI](https://img.shields.io/pypi/v/clawzero)
![CI](https://img.shields.io/github/actions/workflow/status/mvar-security/clawzero/test.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://opensource.org/license/Apache-2.0)

> Powered by MVAR: https://github.com/mvar-security/mvar

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/clawzero-header-banner-dark-mode-vf.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/clawzero-header-banner-light-mode-vf.png">
  <img alt="ClawZero Header" src="docs/assets/clawzero-header-banner-light-mode-vf.png" width="760">
</picture>

<h2>ClawZero is an execution firewall for AI agents.</h2>

<p>
Blocks CVE-2026-25253, malicious ClawHub skills, and persistent memory injection.<br/>
50/50 deterministic block rate in the validation corpus across 9 attack categories. Zero-config API.<br/>
<strong>Powered by MVAR, the runtime for secure AI agents.</strong>
</p>

<p>
Same input. Same agent. Different execution boundary.<br/>
ClawZero enforces policy between model output and tool execution.
</p>

<p>
<a href="https://pypi.org/project/clawzero/"><strong>Install from PyPI</strong></a> •
<a href="docs/index.md"><strong>Documentation</strong></a> •
<a href="docs/integration-quickstarts.md"><strong>Integration Quickstarts</strong></a>
</p>

<p>
<a href="#30-second-quickstart">Quick Start</a> •
<a href="#why-clawzero">Why ClawZero</a> •
<a href="#attack-demo-proof">Attack Demo</a> •
<a href="#canonical-witness-artifact">Witness Artifact</a>
</p>

</div>

**Execution boundary for OpenClaw agents. Powered by MVAR.**

```bash
pip install clawzero==0.2.0
clawzero doctor openclaw
clawzero demo openclaw --mode compare --scenario shell
```

```text
Standard OpenClaw -> COMPROMISED
ClawZero -> BLOCKED ✓
```

Standard OpenClaw executes the attack.
ClawZero blocks it deterministically.

ClawZero places a deterministic execution boundary between model output and tool execution.

![ClawZero vs Standard OpenClaw](docs/assets/comparison.png)

## 30-Second Quickstart

```bash
pip install clawzero==0.2.0
clawzero doctor openclaw
clawzero demo openclaw --mode compare --scenario shell
```

Expected output:

```text
Runtime......... OK (mvar-security 1.4.3)
Witness......... OK (chain valid)
Demo............ OK (attack blocked)
Status: SECURE

STANDARD OPENCLAW  →  COMPROMISED
MVAR-PROTECTED     →  BLOCKED ✓
Witness generated  →  YES
```

## OpenClaw Security Crisis

220,000+ exposed instances. 50,000+ RCE-vulnerable via CVE-2026-25253. 1,184 malicious ClawHub skills discovered.

ClawZero blocks exploitation at the execution boundary before credentials leak, before shells execute, and before data exfiltrates.

## Addresses 5 of 7 DigitalOcean OpenClaw Security Challenges

| Challenge | ClawZero Defense | Command |
|-----------|------------------|---------|
| #1 WebSocket RCE | `trusted_websocket_origins` checks + exposure diagnostics | `clawzero doctor openclaw` |
| #3 Malicious Skills | `UNSIGNED_MARKETPLACE_PACKAGE` enforcement in `prod_locked` | `clawzero audit decision --profile prod_locked --sink-type tool.custom --target install_skill --package-source clawhub --package-hash sha256:deadbeef --publisher-id unknown-publisher` |
| #4 Credential exfil | Credential sink boundary enforcement | `clawzero demo openclaw --mode compare --scenario credentials` |
| #5 Persistent memory | Temporal taint tracking with delayed-trigger enforcement mode | `pytest -q tests/test_phaseC_temporal_taint.py` |
| #6 Shadow AI | Witness artifacts + `doctor` posture checks | `clawzero doctor openclaw` |

## Persistent Memory Injection Protection

ClawZero detects delayed-activation attacks where malicious instructions are embedded in agent memory and trigger days later.

Day 1: Agent reads a malicious document.  
Day 3: Hidden instruction triggers.  
ClawZero: delayed taint reason code path blocks in enforce mode.

Note: We are not aware of other open-source implementations of temporal taint tracking for AI agents.

Reference: `tests/test_phaseC_temporal_taint.py`.

## Enterprise Features

- Compliance-ready audit logs (SARIF export)
- Budget controls (spending limits and abuse detection)
- Package trust validation (blocks unsigned ClawHub skills in `prod_locked`)
- Network isolation controls (`localhost_only` / `allowlist_only`)
- Cryptographically signed witness artifacts
- `clawzero doctor openclaw` posture check (`Status: SECURE`)

## ClawZero vs Alternatives

Based on public positioning:

- VellaVeto: MCP-specific firewall with formal-verification focus, not OpenClaw-native.
- NemoClaw: NVIDIA managed platform, currently alpha/waitlist.
- Sage: Detection-and-response model that alerts after attempts.
- ClawZero: zero-config runtime enforcement, IFC taint-aware policy, production-ready today.

Decision shortcuts:

- Need formal-verification-first MCP posture: VellaVeto.
- Need managed platform lifecycle: NemoClaw (when GA).
- Need detection + response workflow: Sage.
- Need zero-config execution firewall: ClawZero.

## Adapters

OpenClaw adapter is included and works out of the box:

```bash
pip install clawzero
```

LangChain adapter code is included, and requires LangChain packages in your project:

```bash
pip install clawzero langchain langchain-openai
```

## LangChain Integration

```python
from clawzero.adapters.langchain import protect_langchain_tool

safe_tool = protect_langchain_tool(
    my_langchain_tool,
    sink="filesystem.read",
    profile="prod_locked",
)
```

Run the packaged example:

```bash
python examples/langchain_integration.py
```

## Protect Entire Agents

```python
from clawzero import protect_agent

safe_agent = protect_agent(agent, profile="prod_locked")
```

`protect_agent()` auto-detects common framework patterns and wraps registered tools with deterministic sink enforcement.

## Additional Framework Adapters

CrewAI and AutoGen adapters are now included alongside OpenClaw and LangChain:

```python
from clawzero.adapters.crewai import protect_crewai_tool
from clawzero.adapters.autogen import protect_autogen_function
```

MCP adapter alpha is now available:

```python
from clawzero.adapters.mcp import MCPAdapter

adapter = MCPAdapter(profile="prod_locked")
safe_client = adapter.wrap_client(mcp_client, method_name="call_tool")
```

## Attack Pack Validation (50 Vectors)

Run the packaged attack corpus:

```bash
pytest tests/attack_pack/ -v
```

Categories covered: command injection, path traversal, credential exfiltration, data exfiltration, persistence, lateral movement, supply chain, social engineering, and denial of service.

## Benchmark

Measure policy decision latency:

```bash
python -m clawzero.benchmark --iterations 1000
```

This reports per-scenario mean/p95/p99 latency and throughput for deterministic sink enforcement.

## Why ClawZero?

Autonomous AI agents frequently execute tool calls with high privileges.

When these agents ingest untrusted input, prompt injection can escalate into:
- shell execution
- filesystem access
- credential leakage
- data exfiltration

ClawZero prevents these escalations by enforcing deterministic policy checks at execution sinks before commands run.

## Threat Model

OpenClaw agents commonly run with tools capable of:
- shell execution
- filesystem access
- credential retrieval
- outbound network requests

When these agents process untrusted documents or user input, hidden instructions can influence tool calls.

Without an execution boundary, these instructions can trigger high-privilege operations.

ClawZero intercepts these tool calls and enforces policy before execution occurs.

## Attack Demo Proof

The attack demo exists to demonstrate runtime enforcement behavior.

ClawZero is not a model safety claim.

It is an execution boundary claim.

The demo illustrates how untrusted input can influence agent tool calls and how the ClawZero boundary blocks those actions deterministically.

Run the side-by-side comparison:

```bash
clawzero demo openclaw --mode compare --scenario shell
clawzero demo openclaw --mode compare --scenario credentials
clawzero demo openclaw --mode compare --scenario benign
```

## Security and Responsible Use

ClawZero is a defensive security component designed to enforce execution boundaries for AI agents.

The project includes attack demonstrations and adversarial scenarios to show how prompt injection and untrusted inputs can reach high-privilege execution sinks.

These demonstrations exist solely for defensive research and education.

When using ClawZero or its demonstrations:
- Only test systems you own or have explicit authorization to evaluate
- Run demonstrations in sandboxed or isolated environments
- Treat automated results as signals; verify findings manually

ClawZero is designed to prevent exploitation, not enable it.

The attack demonstrations show how enforcement works; they are not tools for performing real-world attacks.

## Canonical Witness Artifact

```json
{
  "timestamp": "2026-03-12T10:00:00Z",
  "agent_runtime": "openclaw",
  "sink_type": "shell.exec",
  "target": "bash",
  "decision": "block",
  "reason_code": "UNTRUSTED_TO_CRITICAL_SINK",
  "policy_id": "mvar-security.v1.4.3",
  "engine": "mvar-security",
  "provenance": {
    "source": "external_document",
    "taint_level": "untrusted",
    "source_chain": ["external_document", "openclaw_tool_call"],
    "taint_markers": ["prompt_injection", "external_content"]
  },
  "adapter": {
    "name": "openclaw",
    "mode": "event_intercept",
    "framework": "openclaw"
  },
  "witness_signature": "ed25519:d91fd8f73f3d05f8ec7b3d8e5e7cf2e27869a5f0f1ee3bd17da2df5ec41c9cb2a3c7e4f3540b4f7f4f948f0f185318273447bcb0adf24a4b2a1b53b7a1b2c90a"
}
```

## What ClawZero Is / Is Not

**ClawZero is:**
- an in-path runtime enforcement substrate
- deterministic sink policy evaluation
- a signed witness artifact generator

**ClawZero is not:**
- a red-team toolkit
- an attack simulation platform
- an LLM-as-judge safety layer

## CLI

Command families map to enforcement jobs:

- `clawzero prove` - run install-to-proof validation in one command
- `clawzero demo` - run side-by-side enforcement proof demos
- `clawzero witness` - inspect and validate witness artifacts
- `clawzero audit` - evaluate deterministic decisions for sink requests
- `clawzero attack` - replay known attack scenarios as enforcement proofs
- `clawzero report` - export witness artifacts to SARIF for code scanning

Note: `clawzero prove` is available on the main branch and will be included in the next PyPI release.

## Zero-Config API

```python
from clawzero import protect

safe_tool = protect(
    my_tool,
    sink="filesystem.read",
    profile="prod_locked"
)
```

## Policy Profiles

| Sink Type             | dev_balanced                                  | dev_strict                            | prod_locked                                |
|----------------------|-----------------------------------------------|----------------------------------------|---------------------------------------------|
| `shell.exec`         | block                                         | block                                  | block                                       |
| `filesystem.read`    | allow, block `/etc/**`, `~/.ssh/**`           | block, allow `/workspace/**`           | block, allow `/workspace/project/**`        |
| `filesystem.write`   | allow, block `/etc/**`, `~/.ssh/**`           | block, allow `/workspace/**`           | block, allow `/workspace/project/**`        |
| `credentials.access` | block                                         | block                                  | block                                       |
| `http.request`       | allow                                         | allow mode + block all domains         | allow mode + allow `localhost`              |
| `tool.custom`        | allow                                         | annotate                               | allow                                       |

## Powered by MVAR

MVAR is the enforcement engine.
ClawZero is the OpenClaw adapter.
MVAR governs the sink policy enforcement decisions.

- MVAR repository: https://github.com/mvar-security/mvar
- Filed as provisional patent (February 24, 2026, 24 claims)
- Submitted to NIST RFI Docket NIST-2025-0035
- Published as preprint on SSRN (February 2026)

## Early Release - Join Us

This is early. The clawzero demo shows enforcement in harness + OpenClaw simulation.

Real multi-turn agent testing is next.

If you're running agents (LangChain, CrewAI, AutoGen, OpenClaw, etc.) and want to try it live:
- DM @Shawndcohen on X
- Open an issue with your setup/framework

Happy to pair debug and share results.

## License

Apache 2.0
