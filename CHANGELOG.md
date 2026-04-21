# Changelog

All notable changes to ClawZero are documented in this file.

## [0.4.0] - 2026-04-16

### Added

- Added enforcement-strength generated test surfaces and audit artifacts on top of `v0.3.0`, including:
  - policy matrix, witness integrity, OWASP ASI-2026, EU AI Act, adversarial evasion, adapter matrix, cross-session isolation, SARIF export, engine parity, and fuzzing suites added across commits `ac2ebd6` through `d32190a`.
  - documented audit baseline and authoring standard in:
    - `docs/test-suite-audit-summary.md`
    - `docs/test-authoring-guide.md`
- Added compliance attestation CLI surface in `clawzero compliance verify` (commit `6776cdf`; hardened in later commits), including signed attestation payload output and suite presence checks.
- Added official SARIF schema validation contracts (`tests/exports/test_sarif_official_schema_contract.py`, commit `db4db6e`).

### Security Hardening (Post-PR81–PR86 MVAR Baseline)

- Integrated and validated against the post-PR81–PR86 MVAR hardening baseline (`52f2038`, `6fbbb89`, `174beee`, `7513c7f`, `3f53bc7`, `a9a1dfd`) used in this workspace:
  - Ed25519 default signing with truthful algorithm labeling (`ed25519` vs `hmac-sha256`), removing algorithm-label misrepresentation in audit output.
  - Vault-mediated credential execution path for `credentials.access`, with token-reference mediation and no raw credential material returned to the agent path.
  - Cryptographic policy lineage enforcement with lineage-chain verification and fail-closed behavior in `prod_locked`.
  - Advanced risk scoring in the default execution path with profile-aware modes (`BLOCKING` in `prod_locked`) and counterfactual injection signals.
  - Taint-laundering prevention integration proofs covering single-hop/multi-hop propagation, trust-boundary crossing, source fragmentation, and Claim-18-style provenance differential behavior (`mvar/tests/integration/test_taint_laundering_prevention.py`).
  - Machine-readable architecture registry with signed runtime self-report, layer status, and compatibility matrix (`mvar/mvar-core/architecture.py`).

### Validation

- Full ClawZero suite green on this release line:
  - `9598 passed`
  - `17 skipped` (intentional gap markers)
  - `0 failed`
  - `9615 collected`
- PyPI: `pip install clawzero==0.4.0`
- GitHub: github.com/mvar-security/clawzero

## [0.3.0] - 2026-04-11

### Added

- Added session-level chain detection runtime and session/wrap CLI paths (`f0f48ee`).
- Added key visibility support in CLI and release-aligned witness UX (`f0f48ee`, `926b49a`).

### Changed

- Stabilized CI ordering and SARIF generation lanes for attack-pack workflows (`ddc5aa9`, `efa43bc`, `2ddea65`, `fe10d1f`).
- Narrowed compliance signing key typing for mypy correctness (`54dd1c0`).

## [0.2.1] - 2026-04-09

### Added

- Added MCP adapter alpha support and strengthened proof UX in release artifacts (`f31e015`).
- Upgraded witness-signing flow and associated demo/proof ergonomics (`f31e015`).

## [0.2.0] - 2026-03-31

### Added

- Added `protect_agent()` API and the v0.2 framework adapter expansion for LangChain, CrewAI, AutoGen, OpenClaw, and MCP integration surfaces (`99477fe`).
- Added expanded attack corpus coverage and release-proof packaging for the 0.2 line (`99477fe`, `ff5a102`).

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
