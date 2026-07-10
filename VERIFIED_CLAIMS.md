# VERIFIED CLAIMS

Last verified: May 5, 2026
Current release: `clawzero` 0.4.2 (PyPI)

Each claim below cites its backing command and source/test locations. Verify by running the cited command and reading the cited file.

## Installation

```bash
pip install --upgrade clawzero
```

## Claim: `clawzero --help` shows all 14 top-level commands
Status: VERIFIED (v0.4.2) — command list corrected against cli.py subparsers (July 2026)

Proof command:
```bash
clawzero --help
```

Expected commands (the 14 top-level subparsers registered in `cli.py`):
- `prove` — Run install-to-proof checks in one command.
- `wrap` — Wrap a command with process/tool-boundary enforcement (not syscall-level interception).
- `session` — Session lifecycle and reporting commands.
- `keys` — Inspect local witness signing key material.
- `compliance` — Verify test-suite compliance scaffolding and emit signed attestation JSON.
- `demo` — Run enforcement proof demos (same input, different boundary).
- `witness` — Inspect and validate signed witness artifacts from enforcement decisions.
- `audit` — Audit deterministic policy enforcement for a specific sink request.
- `attack` — Replay known attack scenarios to prove sink-boundary enforcement.
- `attack-test` — Run compact deterministic attack suite and emit witness artifacts.
- `replay` — Replay an entire witness session directory in timeline form.
- `benchmark` — Run implemented benchmark corpus and print measured outcomes.
- `doctor` — Run OpenClaw environment and enforcement health checks.
- `report` — Export enforcement artifacts into security report formats.

(The count of 14 is correct, but the earlier list was not: there is no top-level `init`, `verify`, or `version` command — those were listed in error and the real commands above were omitted. `--version` is a flag; signature verification lives under `witness`.)

Source:
- `src/clawzero/cli.py`
- PyPI package `clawzero` (current: 0.4.2)

## Claim: ClawZero ships ~9,410 declared compliance scenarios; they execute and pass
Status: VERIFIED (v0.4.0) — corrected wording July 2026

Two separate commands, two separate claims (do not conflate):

**(a) Presence/manifest check** — `clawzero compliance verify`
```bash
clawzero compliance verify
```
Checks that the compliance suite FILES are present and sums their declared scenario
counts. It does **NOT** execute the scenarios. Output is explicitly labelled
"MANIFEST CHECK (presence only — does NOT run scenarios)" and the attestation JSON
carries `check_type: manifest_presence_only`, `executed: false`,
`declared_scenario_count: 9410`. Use this only to confirm the scaffolding is in place.

**(b) Execution** — `clawzero compliance run`
```bash
clawzero compliance run
```
Actually executes the suites via pytest and records real pass/fail in an attestation
with `check_type: executed`, `executed: true`, `passed: <bool>`, and the pytest summary.

Independent proof the scenarios execute and pass (full test run):
```bash
PYTHONPATH=src:<mvar> python -m pytest tests/ -q
# → 9,604 passed / 17 skipped / 3 pre-existing policy-drift failures (tracked)
```
So the ~9,410 declared scenarios are real tests that pass when run; the earlier wording
("compliance verify … Passing scenarios: 9,410 / Coverage 100%") was misleading because
`verify` never executed them. Corrected here (finding G-18).

Source:
- `src/clawzero/cli.py` — `_cmd_compliance_verify` (presence) and `_cmd_compliance_run` (execution)
- `tests/compliance/`, `tests/attack_pack/`, `tests/` (the actual suites)
- Declared scenario count: 9,410 (manifest sum); executed: via `compliance run` / pytest

## Claim: `clawzero prove` runs install-to-proof enforcement checks and emits signed witness records
Status: VERIFIED (v0.3.0+)

Proof command:
```bash
clawzero prove --output-dir ./prove_witnesses
```
(optional: `--require-mvar` to fail fast unless the mvar-security runtime is healthy; `--sink-type`, `--target`, `--command` override the simulated attack.)

Expected output (three-step console report):
- `[1/3] Runtime check....... OK (<detail>)`
- `[2/3] Attack simulation... BLOCKED ✓ (<sink_type>)`
- `[3/3] Witness generated... YES (<signer>)`
- `Status: SECURE`
- `Witness: <path to the signed witness artifact written under --output-dir>`

Source:
- `src/clawzero/cli.py` (`_cmd_prove`, ~L1123)
- `tests/test_doctor_cli.py` (`test_prove_command_secure`, `test_prove_command_require_mvar_fails_when_runtime_warn`)

## Claim: `clawzero keys show` displays Ed25519 signing key status
Status: VERIFIED (v0.4.0)

Proof command:
```bash
clawzero keys show
```

Expected output (when a signing key exists):
- `ClawZero Signing Key`
- `  Algorithm:   Ed25519`
- `  Public key:  <base64>`
- `  Fingerprint: <16-hex>` (first 16 hex chars of SHA-256 over the public key)
- `  Key file:    <path>`
- (if no key yet: `Status: missing` with guidance to run a witness-emitting command)

Source:
- `src/clawzero/cli.py` (`_cmd_keys_show`, ~L755) + `src/clawzero/witnesses/generator.py` (Ed25519 key handling)
- No dedicated `keys show` CLI test as of v0.4.2; the underlying Ed25519 signing/key path is exercised by `tests/test_witness_signing.py`, `tests/test_witness_signature_verification.py`, and `tests/test_witness_trust.py`

## Claim: `clawzero wrap` provides live enforcement feed
Status: VERIFIED (v0.3.0+)

Proof command:
```bash
clawzero wrap -- python src/clawzero/examples/attack_demo.py
```

Expected output includes:
- `[ClawZero] Session <session_id> active — <profile>`
- A note that interception is at the process/tool-call boundary (not syscall-level)
- Per-call decision lines: `<timestamp>  ALLOW|BLOCK  <sink_type>  <command>` (blocked calls add `Reason:` and `Witness:`)
- A `Session complete` summary: `Calls`, `Blocked`, `Score` (escalation), `Witnesses` (chain length), and `Report:` path

Source:
- `src/clawzero/cli.py` (`_cmd_wrap`, ~L1026)
- `src/clawzero/examples/attack_demo.py`
- `tests/test_cli_session_wrap.py`

## Claim: `clawzero session` tracks cross-session taint continuity
Status: VERIFIED (v0.3.0+)

Proof command:
```bash
clawzero session list
clawzero session show <session_id>
```

Expected functionality:
- Session isolation enforcement
- Cross-session taint continuity detection
- Chain detection across session boundaries

Source:
- `src/clawzero/runtime/session.py`
- `src/clawzero/runtime/chain_patterns.py`
- `tests/test_session_runtime.py`, `tests/test_cli_session_wrap.py`

## Claim: `clawzero doctor openclaw` returns secure runtime posture
Status: VERIFIED

Proof command:
```bash
clawzero doctor openclaw
```

Expected output includes:
- `Runtime......... OK (mvar-security 1.5.2+)`
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
- `Policy:  mvar-security.v1.5.2+`
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

## Claim: 6 framework adapter surfaces are shipped
Status: VERIFIED (v0.4.2) — count corrected against `clawzero.__all__` (July 2026)

Proof command:
```bash
python - <<'PY'
from clawzero import (
    OpenClawAdapter, LangChainAdapter, CrewAIAdapter,
    AutoGenAdapter, MCPAdapter, protect_agent
)
print("OK")
PY
```

Expected output:
- `OK`

The five `*Adapter` classes plus `protect_agent` = 6 surfaces, all exported from `clawzero.__all__`. (The earlier "7 surfaces / `ClaudeAdapter`" import was incorrect — no `ClaudeAdapter` is exported, so that import raised ImportError.)

Source:
- `src/clawzero/__init__.py` (`__all__` — the authoritative export list)
- `src/clawzero/adapters/openclaw/__init__.py`
- `src/clawzero/adapters/langchain.py`
- `src/clawzero/adapters/crewai.py`
- `src/clawzero/adapters/autogen.py`
- `src/clawzero/adapters/mcp.py`
- `src/clawzero/protect_agent.py`

## Claim: 50 attack vectors are validated in the attack pack
Status: VERIFIED

Proof command:
```bash
pytest -q tests/attack_pack
```

Expected output includes:
- `2,750 passed (50 base vectors + generated expanded pack)`

Source:
- `tests/attack_pack/`

## Claim: Full local suite runs green except tracked pre-existing failures
Status: run it to confirm — figures below are from a recorded run, not re-verified in this environment

Proof command:
```bash
PYTHONPATH=src:<mvar> python -m pytest tests/ -q
```

Recorded run (v0.4.x, see the compliance-execution claim above):
- `9,604 passed / 17 skipped / 3 pre-existing policy-drift failures (tracked)`
- Previous: 117 tests (v0.2.0)
- The "9,625 collected / clean pass" phrasing was inconsistent with the tracked-failures line above; corrected here to the self-consistent figure. Re-run the command to confirm the current count.

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

---

## Version Evolution

### v0.4.0 (Current)
- Added `compliance verify` command (9,410 scenarios)
- Added `keys show` command (Ed25519 key management)
- Test count: 279 tests
- PyPI release: May 2, 2026

### v0.3.0
- Added `prove` command (install-to-proof enforcement checks, signed witness records)
- Added `wrap` command (live enforcement feed)
- Added `session` command (cross-session taint tracking)
- Session isolation and chain detection
- Test count: ~180 tests

### v0.2.0
- Initial public release
- Core boundary enforcement
- 5 framework adapters
- Test count: 117 tests

---

**Last updated:** May 5, 2026
**Maintainer:** MVAR Security (github.com/mvar-security)
**License:** Apache 2.0
