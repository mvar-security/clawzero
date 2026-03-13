# Contributing to ClawZero

Thanks for contributing.

## Ground Rules

- Preserve deterministic enforcement semantics.
- Keep ClawZero positioned as an in-path enforcement substrate.
- Do not reframe the project as attack-simulation-first.
- Maintain witness schema compatibility.

## Development

```bash
pytest tests/test_claims.py -v
python demo/openclaw_attack_demo.py --mode compare --scenario shell
```

## Pull Requests

Please include:

- concise problem statement
- design approach
- tests and verification output
- contract/schema impact (if any)
