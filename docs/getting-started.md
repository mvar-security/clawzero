# Getting Started

## Install

```bash
pip install clawzero==0.2.0
```

## Run the Enforcement Proof

```bash
clawzero doctor openclaw
clawzero demo openclaw --mode compare --scenario shell
```

If `clawzero` is not on PATH in your shell:

```bash
PYTHONPATH=src python -m clawzero.cli doctor openclaw
PYTHONPATH=src python -m clawzero.cli demo openclaw --mode compare --scenario shell
```

Expected outcome:

- Runtime check: SECURE
- Standard OpenClaw path: compromised
- ClawZero + MVAR path: blocked
- Witness artifact: generated

## One-Command Proof (Main Branch / Next Release)

```bash
clawzero prove --require-mvar
```

This command combines runtime health, attack simulation, and witness generation.

## Core API

```python
from clawzero import protect

safe_tool = protect(my_tool, sink="shell.exec", profile="prod_locked")
```

## Responsible Use

Only run demonstrations against systems you own or are explicitly authorized to test.
