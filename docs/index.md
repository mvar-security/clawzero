# ClawZero

ClawZero is a deterministic **in-path execution boundary** for OpenClaw agent flows.

ClawZero sits between model output and tool execution. MVAR policy evaluation decides whether a sink call is allowed, blocked, or annotated, then emits signed witness artifacts.

## Responsible Use

ClawZero includes adversarial demonstrations to illustrate how prompt
injection can propagate to execution sinks.

These examples are provided solely for defensive research and education.

Only test systems you own or have explicit authorization to evaluate.

## What ClawZero Is

- A runtime enforcement substrate for live agent execution paths
- A deterministic policy gate at critical sinks
- A witness-producing control plane for auditability

## What ClawZero Is Not

- A red-team toolkit
- An attack simulation platform first
- An LLM-as-judge safety layer

Use the attack demo as **proof of enforcement**, not as the product center.
