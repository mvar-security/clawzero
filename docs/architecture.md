# Architecture

## Execution Path

OpenClaw tool request -> ClawZero adapter -> MVAR runtime `evaluate()` -> decision -> sink execution (or block) -> witness artifact

## Layer Roles

- `clawzero.adapters.openclaw`: framework integration and request shaping
- `clawzero.runtime`: policy evaluation engine (MVAR-first, deterministic fallback)
- `clawzero.witnesses`: canonical witness generation and signing stub

## Deterministic Boundary vs LLM-as-Judge

ClawZero does not rely on a model-generated safety verdict to authorize sink execution.

It enforces deterministic policy logic in-path before execution. This produces reproducible decisions and auditable witness artifacts.

## Positioning Contrast

Simulation/evaluation tooling measures susceptibility.

ClawZero enforces controls in the live execution path.

The attack demo validates boundary behavior; ClawZero itself is the in-path enforcement substrate.
