# Policies

ClawZero supports three profiles:

- `dev_balanced`
- `dev_strict`
- `prod_locked`

These profiles map sink classes to deterministic allow/block/annotate behavior.

MVAR runtime availability is explicit via runtime engine selection:

- `mvar-security` (preferred)
- `embedded-policy-v0.1` (deterministic fallback)
