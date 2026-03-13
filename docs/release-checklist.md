# Release Checklist

Use this checklist before publishing a release.

## Fresh Clone Validation

```bash
git clone https://github.com/mvar-security/clawzero
cd clawzero
pip install -e .
```

## Demo Proof Sequence

```bash
clawzero demo openclaw --mode compare --scenario shell
clawzero demo openclaw --mode compare --scenario credentials
clawzero demo openclaw --mode compare --scenario benign
```

Expected outcomes:

- shell: Standard compromised, MVAR path blocked, witness generated
- credentials: Standard compromised, MVAR path blocked, witness generated
- benign: Standard allowed, MVAR path allowed, witness generated

## Integration Example

```bash
python examples/openclaw_integration.py
```

Expected outcome:

- critical sink actions blocked with `MVAR blocked: ...`
- allowlisted safe actions allowed

## Test Suite

```bash
pytest tests/test_claims.py -v
```

Expected outcome:

- `23 passed`

## Packaging Sanity

```bash
python -m py_compile $(find src demo examples tests -name '*.py')
```

Expected outcome:

- no compile errors
