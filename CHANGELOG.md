# Changelog

All notable changes to ClawZero are documented in this file.

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
