# Release Proof — ClawZero 0.1.5

This document is a copy-paste proof pack for validating the `0.1.5` release.

## 1) Clean Install From PyPI

```bash
python3 -m venv /tmp/clawzero_015_verify
source /tmp/clawzero_015_verify/bin/activate
pip install --no-cache-dir clawzero==0.1.5
```

Expected:
- install succeeds
- `mvar-security>=1.4.0` is resolved

## 2) Doctor Check

```bash
clawzero doctor openclaw
```

Expected lines include:
- `Runtime......... OK (mvar-security 1.4.3)`
- `Witness......... OK (chain valid)`
- `Demo............ OK (attack blocked)`
- `Exposure........ OK (control-plane guards active)`
- `Witness signer:  Ed25519 (QSEAL) ✓`
- `Status: SECURE`

## 3) Shell Compare Demo

```bash
clawzero demo openclaw --mode compare --scenario shell --output-dir /tmp/clawzero_015_witnesses
```

Expected lines include:
- `Standard OpenClaw   →  COMPROMISED`
- `MVAR-Protected      →  BLOCKED ✓`
- `Policy:  mvar-security.v1.4.3`
- `Reason:  UNTRUSTED_TO_CRITICAL_SINK`

## 4) Witness Verify

```bash
clawzero witness verify --file /tmp/clawzero_015_witnesses/witness_001.json
```

Expected:
- `VALID`

## 5) Witness Chain Verify

```bash
clawzero witness verify-chain --dir /tmp/clawzero_015_witnesses
```

Expected:
- `CHAIN VALID`

## 6) Package Trust Block Proof

```bash
clawzero audit decision \
  --profile prod_locked \
  --sink-type tool.custom \
  --target install_skill \
  --package-source clawhub \
  --package-hash sha256:deadbeef \
  --publisher-id unknown-publisher
```

Expected lines include:
- `decision   : block`
- `reason     : UNSIGNED_MARKETPLACE_PACKAGE`
- `pkg_trust  : block (UNSIGNED_MARKETPLACE_PACKAGE)`

## 7) Temporal Taint and Budget Proof (test-backed)

```bash
pytest -q tests/test_phaseC_temporal_taint.py
pytest -q tests/test_phaseD_budget_controls.py
```

Expected:
- both test files pass
- temporal enforce-path reason code: `DELAYED_TAINT_TRIGGER`
- budget over-limit reason code: `BUDGET_LIMIT_EXCEEDED`
