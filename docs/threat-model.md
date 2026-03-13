# Threat Model

## Threat

Prompt injection and untrusted context can coerce autonomous agents into critical sink actions.

## Control Objective

Prevent attacker-controlled sink execution by placing deterministic policy enforcement between model output and runtime sink calls.

## Scope

ClawZero governs sink classes such as:

- `shell.exec`
- `filesystem.read`
- `credentials.access`
- `http.request`

## Why Deterministic Enforcement

LLM-as-judge safety gates can be non-deterministic and hard to audit.

ClawZero uses deterministic runtime policy enforcement so critical sink actions are evaluated consistently and produce witness evidence.

## Simulation vs Enforcement

Attack simulation tooling is useful for validation, but it is not a production boundary.

ClawZero is designed to be deployed in-path so critical sink calls are deterministically evaluated before execution.

The attack demo is included as proof of enforcement behavior, not as a simulation-first product.
