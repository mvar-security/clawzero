# Changelog

All notable changes to ClawZero are documented in this file.

## [0.1.5] - 2026-03-18

### Added

- Added Phase C temporal-taint controls in runtime evaluation, including delayed-trigger detection and configurable temporal mode (`warn`/`enforce`).
- Added Phase D budget and abuse controls (`max_cost_usd`, per-window call limits, per-sink call limits) with charging policies (`SUCCESS_BASED`, `ATTEMPT_BASED`).
- Added witness fields for temporal and budget evidence:
  - `temporal_taint_status`
  - `delayed_trigger_detected`
  - `taint_age_hours`
  - `budget_status`
- Added test coverage:
  - `tests/test_phaseC_temporal_taint.py`
  - `tests/test_phaseD_budget_controls.py`
  - `tests/test_phase4_cli.py`

### Changed

- Updated replay/explain CLI surfaces to expose temporal-taint context in operator-facing output.
- Updated witness generation typing fallback for budget metadata to keep mypy strict checks green.

## [0.1.4] - 2026-03-18

### Added

- Added control-plane exposure check line in `clawzero doctor openclaw` output.
- Added clearer signer messaging to distinguish witness signing and ledger fallback:
  - `Witness signer:  Ed25519 (QSEAL) ✓`
  - `Ledger signer:   HMAC fallback (external signer not configured)`

### Changed

- Updated canonical demo witness output to current MVAR-backed schema (`schema_version: 1.1`, chain fields, policy/engine attribution).

## [0.1.3] - 2026-03-18

### Added

- Added `clawzero doctor openclaw` command with runtime, witness-chain, and attack-demo checks.
- Added doctor CLI tests for secure path, warn-no-mvar path, and invalid-chain handling.

## [0.1.2] - 2026-03-15

### Added

- Added `clawzero witness explain` for human-readable decision explanation from witness artifacts.
- Added `clawzero replay --session ...` to reconstruct and summarize session timelines.
- Added `clawzero attack-test` compact deterministic attack suite output for launch demos.
- Added `clawzero benchmark run --profile ...` with explicit implemented corpus counts.
- Added `VERIFIED_CLAIMS.md` mapping public claims to concrete tests/CLI proofs.
- Added Phase 4 CLI tests covering explain, replay, attack-test, benchmark contracts, and claims file presence.

### Changed

- Updated CLI help and command layout to include replay and benchmark surfaces.
- Updated package version to `0.1.2`.

## [0.1.1] - 2026-03-13

### Fixed

- Fixed installed-environment demo execution: `clawzero demo openclaw ...` now runs package module code instead of repo-relative script paths.
- Packaged demo implementation under `src/clawzero/demo/` so the demo is available after `pip install clawzero`.
- Included required demo assets (including `attack_payloads/quarterly_report.md`) in package data.
- Added packaged examples under `src/clawzero/examples/` for install-time availability.
- Added package-data exclusion rules for `__pycache__`/`.pyc` to prevent shipping bytecode artifacts.
- Updated witness output path behavior in packaged demo to prefer local `./demo/expected_outputs` writes.

## [0.1.0] - 2026-03-13

### Added

- Deterministic MVAR-first execution runtime with explicit embedded fallback
- OpenClaw adapter for wrapped-tool and event-intercept enforcement paths
- Canonical witness artifacts with signed witness signature field and provenance
- OpenClaw attack demo proving same-input/different-boundary outcomes
- Enforcement-first CLI command groups:
  - `clawzero demo`
  - `clawzero witness`
  - `clawzero audit`
  - `clawzero attack`
- `src/` package layout and modern packaging configuration
- MkDocs documentation skeleton and core architecture/threat-model docs
- Trust and governance docs:
  - `SECURITY.md`
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
- CI workflow for lint/type/test checks (`ruff`, `mypy`, `pytest`)

### Positioning

- ClawZero is an in-path enforcement substrate for production agent flows
- MVAR is the enforcement engine
- Attack demos are proof-of-enforcement artifacts, not product center
