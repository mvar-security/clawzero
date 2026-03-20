# VERIFIED CLAIMS

Last verified: March 20, 2026  
Release target: `clawzero==0.1.5`

All claims below are command-backed and reproducible in the current repository and release.

## Claim: `clawzero doctor openclaw` returns secure runtime posture
Status: VERIFIED

Proof command:
```bash
clawzero doctor openclaw
```

Expected output includes:
- `Runtime......... OK (mvar-security 1.4.3)`
- `Witness......... OK (chain valid)`
- `Demo............ OK (attack blocked)`
- `Exposure........ OK (control-plane guards active)`
- `Witness signer:  Ed25519 (QSEAL) ✓`
- `Status: SECURE`

Source:
- `src/clawzero/doctor.py`
- `tests/test_doctor_cli.py`

## Claim: Shell injection is blocked at the execution boundary
Status: VERIFIED

Proof command:
```bash
clawzero demo openclaw --mode compare --scenario shell
```

Expected output includes:
- `Standard OpenClaw   →  COMPROMISED`
- `MVAR-Protected      →  BLOCKED ✓`
- `Policy:  mvar-security.v1.4.3`
- `Reason:  UNTRUSTED_TO_CRITICAL_SINK`

Source:
- `src/clawzero/demo/openclaw_attack_demo.py`
- `tests/test_claims.py`

## Claim: Unsigned ClawHub packages are blocked in `prod_locked`
Status: VERIFIED

Proof command:
```bash
clawzero audit decision \
  --profile prod_locked \
  --sink-type tool.custom \
  --target install_skill \
  --package-source clawhub \
  --package-hash sha256:deadbeef \
  --publisher-id unknown-publisher
```

Expected output includes:
- `decision   : block`
- `reason     : UNSIGNED_MARKETPLACE_PACKAGE`
- `pkg_trust  : block (UNSIGNED_MARKETPLACE_PACKAGE)`

Source:
- `tests/test_phaseB_package_trust.py`
- `tests/test_phaseB_cli_package_trust.py`

## Claim: Temporal taint can block delayed activation from memory traces
Status: VERIFIED

Proof command:
```bash
pytest -q tests/test_phaseC_temporal_taint.py
```

Expected test assertion includes:
- `decision.reason_code == "DELAYED_TAINT_TRIGGER"`
- `taint_age_hours > delayed_taint_threshold_hours` path blocks in enforce mode

Source:
- `src/clawzero/runtime/engine.py`
- `tests/test_phaseC_temporal_taint.py`

## Claim: Budget and abuse controls deterministically block over-limit requests
Status: VERIFIED

Proof command:
```bash
pytest -q tests/test_phaseD_budget_controls.py
```

Expected test assertions include:
- `decision.reason_code == "BUDGET_LIMIT_EXCEEDED"`
- block when configured cost/call ceilings are exceeded

Source:
- `src/clawzero/runtime/engine.py`
- `tests/test_phaseD_budget_controls.py`

## Claim: Witness artifacts are valid and hash-chain verifiable
Status: VERIFIED

Proof commands:
```bash
clawzero witness verify --file <witness.json>
clawzero witness verify-chain --dir <witness_dir>
```

Expected output:
- `VALID`
- `CHAIN VALID (N witnesses)`

Source:
- `src/clawzero/witnesses/generator.py`
- `src/clawzero/witnesses/verify.py`
- `tests/test_witness_trust.py`

## Claim: CI matrix and release gate are green on `main`
Status: VERIFIED

Proof command:
```bash
gh run list --repo mvar-security/clawzero --limit 10
```

Expected recent successful runs include:
- `CI` green across `ubuntu-latest` + `macos-latest` on Python `3.10/3.11/3.12/3.13`
- `release-gate` job: PASS
- `download-smoke` jobs: PASS

Source:
- `.github/workflows/test.yml`

## Claim: Credential-read exfiltration path is blocked in compare mode
Status: VERIFIED

Proof command:
```bash
clawzero demo openclaw --mode compare --scenario credentials
```

Expected output includes:
- `Standard OpenClaw   →  COMPROMISED`
- `MVAR-Protected      →  BLOCKED ✓`
- `Policy:  mvar-security.v1.4.3`

Source:
- `src/clawzero/demo/openclaw_attack_demo.py`
- `tests/test_claims.py`

## Claim: Replay and explain commands produce deterministic human-readable output
Status: VERIFIED

Proof commands:
```bash
pytest -q tests/test_phase4_cli.py -k "witness_explain_output or replay_orders_and_summarizes"
```

Expected:
- witness explain output includes structured sections (`Request`, `Provenance`, `Decision`)
- replay output is ordered and includes a session summary

Source:
- `src/clawzero/cli.py`
- `tests/test_phase4_cli.py`

## Claim: SARIF export generates valid code-scanning payloads
Status: VERIFIED

Proof commands:
```bash
pytest -q tests/test_sarif_export.py
clawzero report sarif --input <witness_dir> --output ./results.sarif
```

Expected:
- SARIF file is generated
- decisions are mapped into SARIF result entries

Source:
- `src/clawzero/sarif.py`
- `tests/test_sarif_export.py`
