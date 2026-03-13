# Getting Started

## Install

```bash
pip install -e .
```

## Run the Enforcement Proof

```bash
clawzero demo openclaw --mode compare --scenario shell
```

If `clawzero` is not on PATH in your shell:

```bash
PYTHONPATH=src python -m clawzero.cli demo openclaw --mode compare --scenario shell
```

Expected outcome:

- Standard OpenClaw path: compromised
- ClawZero + MVAR path: blocked
- Witness artifact: generated

## Core API

```python
from clawzero import protect

safe_tool = protect(my_tool, sink="shell.exec", profile="prod_locked")
```

## Responsible Use

Only run demonstrations against systems you own or are explicitly authorized to test.
