# ClawZero

[![CI](https://github.com/mvar-security/clawzero/actions/workflows/ci.yml/badge.svg)](https://github.com/mvar-security/clawzero/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

**ClawZero is a deterministic in-path enforcement substrate for OpenClaw agent flows.**

ClawZero brings MVAR's execution boundary to OpenClaw agents.

![ClawZero vs Standard OpenClaw](docs/assets/comparison.png)

**Same input. Same agent. Different boundary.**

ClawZero places a deterministic execution boundary between model output and tool execution. Powered by MVAR.
ClawZero is not a model. It's a runtime firewall.
It works with any LLM, any OpenClaw agent, any tool definition.

SAME INPUT. SAME AGENT. DIFFERENT BOUNDARY.
Standard OpenClaw executes the attack.
MVAR blocks it deterministically.

## 30-Second Quickstart

```bash
git clone https://github.com/mvar-security/clawzero
cd clawzero
pip install -e .
clawzero demo openclaw --mode compare --scenario shell
```

Expected output:

```text
STANDARD OPENCLAW  →  COMPROMISED
MVAR-PROTECTED     →  BLOCKED ✓
Witness generated  →  YES
```

## Attack Demo Proof

The attack demo is **proof of enforcement behavior**, not the product center.

ClawZero is not a model-safety claim.
It is an execution-boundary claim.

## Security and Responsible Use

ClawZero is a defensive security component designed to enforce execution
boundaries for AI agents.

The project includes attack demonstrations and adversarial scenarios in
order to illustrate how prompt injection and untrusted inputs can reach
high-privilege execution sinks.

These demonstrations exist solely for defensive research and education.

When using ClawZero or its demonstrations:

- Only test systems you own or have explicit authorization to evaluate
- Run demonstrations in sandboxed or isolated environments
- Treat automated results as signals; verify findings manually

ClawZero is designed to prevent exploitation, not enable it.

The attack demonstrations show how enforcement works; they are not tools
for performing real-world attacks.

## Canonical Witness Artifact

```json
{
  "timestamp": "2026-03-12T10:00:00Z",
  "agent_runtime": "openclaw",
  "sink_type": "shell.exec",
  "target": "bash",
  "decision": "block",
  "reason_code": "UNTRUSTED_TO_CRITICAL_SINK",
  "policy_id": "mvar-embedded.v0.1",
  "engine": "embedded-policy-v0.1",
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
  "witness_signature": "ed25519_stub:abcd1234ef567890"
}
```

## What ClawZero Is / Is Not

**ClawZero is:**

- An in-path runtime enforcement substrate
- Deterministic sink policy evaluation at execution time
- A signed witness artifact generator for auditability

**ClawZero is not:**

- A red-team toolkit
- An attack simulation platform first
- An LLM-as-judge safety layer

## CLI

Command families map to enforcement jobs:

- `clawzero demo` - run side-by-side enforcement proof demos
- `clawzero witness` - inspect and validate witness artifacts
- `clawzero audit` - evaluate deterministic decisions for sink requests
- `clawzero attack` - replay known attack scenarios as enforcement proofs

## OpenClaw Attack Demo

Run the side-by-side comparison:

```bash
clawzero demo openclaw --mode compare --scenario shell
clawzero demo openclaw --mode compare --scenario credentials
clawzero demo openclaw --mode compare --scenario benign
```

## Zero-Config API

```python
from clawzero import protect

safe_tool = protect(my_tool, sink="filesystem.read", profile="prod_locked")
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

- MVAR repository: https://github.com/mvar-security/mvar
- ClawZero is the OpenClaw adapter for MVAR
- MVAR is the enforcement engine behind ClawZero policy decisions

The MVAR execution governance model is:

- Filed as provisional patent (February 24, 2026, 24 claims)
- Submitted to NIST RFI Docket NIST-2025-0035
- Published as preprint on SSRN (February 2026)

## License

Apache 2.0
