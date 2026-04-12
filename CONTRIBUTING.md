# Contributing to ClawZero

Thanks for contributing.

## Ground Rules

- Preserve deterministic enforcement semantics.
- Keep ClawZero positioned as an in-path enforcement substrate.
- Do not reframe the project as attack-simulation-first.
- Maintain witness schema compatibility.
- Follow the enforcement-strength test standard in `docs/test-authoring-guide.md`.

## Development

```bash
pytest tests/test_claims.py -v
python demo/openclaw_attack_demo.py --mode compare --scenario shell
```

For test changes, run targeted suites locally and include output in the PR.

## Pull Requests

Please include:

- concise problem statement
- design approach
- tests and verification output
- contract/schema impact (if any)

## Test Quality Gate

PRs that add or modify tests must satisfy:

- no weak assertions (existence-only / no-op assertions)
- explicit enforcement-path assertions (`decision`, `reason_code`, `sink_type`)
- witness/session assertions where the feature depends on them
- behavior grounded in actual runtime contracts (not aspirational assumptions)
