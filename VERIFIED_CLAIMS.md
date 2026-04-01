# VERIFIED CLAIMS

Last verified: April 1, 2026  
Release target: `clawzero==0.2.0`

All claims below are command-backed and reproducible from the repository.

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

## Claim: Temporal taint enforcement blocks delayed activation traces
Status: VERIFIED

Proof command:
```bash
pytest -q tests/test_phaseC_temporal_taint.py
```

Expected test assertion includes:
- `decision.reason_code == "DELAYED_TAINT_TRIGGER"`
- delayed trigger path blocks in enforce mode

Source:
- `src/clawzero/runtime/engine.py`
- `tests/test_phaseC_temporal_taint.py`

## Claim: Budget controls block over-limit requests deterministically
Status: VERIFIED

Proof command:
```bash
pytest -q tests/test_phaseD_budget_controls.py
```

Expected test assertion includes:
- `decision.reason_code == "BUDGET_LIMIT_EXCEEDED"`

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

## Claim: 5 framework adapter surfaces are shipped
Status: VERIFIED

Proof command:
```bash
python - <<'PY'
from clawzero import OpenClawAdapter, LangChainAdapter, CrewAIAdapter, AutoGenAdapter, protect_agent
print("OK")
PY
```

Expected output:
- `OK`

Source:
- `src/clawzero/adapters/openclaw/__init__.py`
- `src/clawzero/adapters/langchain.py`
- `src/clawzero/adapters/crewai.py`
- `src/clawzero/adapters/autogen.py`
- `src/clawzero/protect_agent.py`

## Claim: 50 attack vectors are validated in the attack pack
Status: VERIFIED

Proof command:
```bash
pytest -q tests/attack_pack
```

Expected output includes:
- `50 passed`

Source:
- `tests/attack_pack/`

## Claim: Full local suite passes at 117 tests
Status: VERIFIED

Proof command:
```bash
pytest tests/ -q
```

Expected output includes:
- `117 passed`

Source:
- `tests/`

## Claim: Decision latency is microsecond-class (~1ms mean on measured run)
Status: VERIFIED

Proof command:
```bash
python -m clawzero.benchmark --iterations 1000
```

Expected output includes:
- `Overall: mean=1082.6us per decision` (hardware/runtime dependent)

Messaging guidance:
- Use `~1ms per decision` or `microsecond-class enforcement`.
- Do not claim `<100us` unless re-measured and reproduced in CI with hardware context.

Source:
- `src/clawzero/benchmark.py`
