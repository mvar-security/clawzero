# ClawZero Test Suite Audit Summary

Date: 2026-04-13

This document is the enforcement-strength baseline from the generated-test audit pass across:

- `tests/attack_pack/test_attack_pack_expanded_generated.py`
- `tests/owasp/test_asi_2026_generated.py`
- `tests/test_policy_matrix_generated.py`
- `tests/compliance/test_eu_ai_act_generated.py`
- `tests/session/test_cross_session_isolation_generated.py`
- `tests/fuzzing/test_engine_fuzz_generated.py`

## What This Suite Guarantees

1. Deterministic decision contracts are asserted (not just decision class membership) for audited generated suites.
2. Witness artifacts are semantically validated (request linkage, decision/reason/sink/target/profile coherence), not just existence-checked.
3. Provenance normalization is tested explicitly (input-class and taint normalization behavior).
4. Coverage boundaries are explicit and machine-visible via intentional `pytest.skip(...)` gap markers.

## Engine Contracts Discovered and Codified

1. `unknown`/`untrusted` normalization to untrusted taint in witness/provenance contexts.
Source evidence:
- `tests/attack_pack/test_attack_pack_expanded_generated.py` (`_expected_witness_taint_level`)
- `tests/owasp/test_asi_2026_generated.py` (`_expected_witness_taint_level`)
- `tests/test_policy_matrix_generated.py` (`_expected_witness_taint_level`)
- `tests/compliance/test_eu_ai_act_generated.py` (`_expected_witness_taint_level`)
- `tests/fuzzing/test_engine_fuzz_generated.py` (`_expected_witness_taint_level`)

2. Input class resolution drives effective profile normalization.
Behavior:
- `dev_balanced` + normalized untrusted input => effective profile `dev_strict`.
Source evidence:
- `src/clawzero/runtime/engine.py` (`_resolve_input_class`, `_apply_input_class_overrides`, `_prepare_request`)
- enforced in all audited generated suites via `effective_policy_profile` assertions.

3. Source-label invariance in policy matrix outcomes.
Behavior:
- For fixed `taint × sink × profile`, source label is coverage metadata and does not change decision contract.
Source evidence:
- `tests/test_policy_matrix_generated.py::test_policy_matrix_contract_source_dimension_is_explicitly_invariant`

4. Filesystem safety guards are layered and dominate permissive paths.
Behavior:
- Traversal/sensitive path patterns block via `PATH_BLOCKED` even where embedded policy might otherwise permit.
Source evidence:
- `src/clawzero/runtime/engine.py` (`_apply_filesystem_safety_guards`)
- codified in `tests/fuzzing/test_engine_fuzz_generated.py` expected-decision logic.

5. Session taint precedence contract in `AgentSession`.
Behavior:
- `ActionDecision.trust_level` is read first by `AgentSession._taint_level`; forged session blobs only affect taint when `trust_level` is absent.
Source evidence:
- `src/clawzero/runtime/session.py` (`_taint_level`)
- codified by contamination-path test in `tests/session/test_cross_session_isolation_generated.py`.

6. Session ownership is local and enforced in enriched annotations.
Behavior:
- Enriched decision `session_id` is always the active session; forged cross-session metadata does not rebind ownership.
Source evidence:
- `tests/session/test_cross_session_isolation_generated.py::test_cross_session_isolation_contamination_attempt_is_fail_closed`

7. EU/OWASP mapping in generated compliance suites is model-based, not full-framework coverage.
Behavior:
- Each modeled control/article maps to explicit sink + reason-code contracts with scope notes.
Source evidence:
- `tests/owasp/test_asi_2026_generated.py` (`ASI_CONTROL_MAPPING_CONTRACTS`, mapping completeness test)
- `tests/compliance/test_eu_ai_act_generated.py` (`EUAI_CONTROL_MAPPING_CONTRACTS`, mapping completeness test)

## Explicit Gap Markers Added (Intentional Boundaries)

1. Policy matrix allow-path boundary
- Test: `tests/test_policy_matrix_generated.py::test_policy_matrix_gap_filesystem_read_allow_paths_not_covered`
- Why: file pins `filesystem.read` to `/etc/passwd` block-path contract; allowlist workspace read paths are intentionally out of scope for this matrix file.

2. ASI cross-category chaining boundary
- Test: `tests/owasp/test_asi_2026_generated.py::test_asi_cross_category_taint_chain_coverage_gap_is_explicit`
- Why: suite validates per-control primary sink contracts only; cross-category taint-chain scenarios are intentionally not claimed here.

3. EU AI Act process-obligation boundary
- Test: `tests/compliance/test_eu_ai_act_generated.py::test_eu_ai_act_gap_aug_2026_unmodeled_obligations_are_explicit`
- Why: suite models runtime sink enforcement, not process-heavy obligations (technical documentation evidence workflows, conformity/CE-marking workflows, broader incident/reporting process obligations).

4. Session isolation breach signaling boundary
- Test: `tests/session/test_cross_session_isolation_generated.py::test_cross_session_isolation_gap_dedicated_breach_reason_code_not_implemented`
- Why: runtime currently fail-closes via taint/escalation but does not emit a dedicated `ISOLATION_BREACH` reason code / alert channel.

5. Legacy-vs-extended fuzz dedup boundary
- Test: `tests/fuzzing/test_engine_fuzz_generated.py::test_engine_fuzz_generated_gap_cross_suite_dedup_not_enforced`
- Why: both suites are now strong, but formal dedup ownership boundaries are not yet machine-enforced.

## Fuzz Suites: Overlap and Consolidation Recommendation

### Observed coverage relationship

- Legacy suite: `tests/fuzzing/test_engine_fuzz_generated.py`
  - 1000 cases
  - deterministic runtime contract assertions
  - 21 unique behavior signatures observed in audit analysis

- Extended suite: `tests/fuzzing/test_engine_fuzz_extended_generated.py`
  - 960 generic matrix cases + 48 targeted adversarial cases
  - targeted classes: prompt-injection boundaries, tool-chaining abuse, encoding policy escapes

- Relationship from audit analysis:
  - overlap exists but is partial
  - suites are not pure duplicates; each covers behaviors the other does not assert explicitly

### Recommended consolidation (do not execute silently)

1. Keep both suites but assign explicit ownership:
- Legacy fuzz (`test_engine_fuzz_generated.py`): runtime contract and normalization/guard invariants.
- Extended fuzz (`test_engine_fuzz_extended_generated.py`): adversarial scenario classes and exploit-shape behaviors.

2. Add a follow-up `fuzz-coverage-manifest` document/test that declares:
- which behavior classes are owned by legacy vs extended
- which classes are intentionally shared
- what constitutes disallowed duplicate growth

3. Keep the current explicit gap marker until manifest enforcement exists.

## Due-Diligence Interpretation

This audited suite is designed to be honest under review:

- It makes modeled contracts explicit.
- It does not imply coverage where none exists.
- It records intentional omissions as executable skip markers.
- It separates runtime-enforcement guarantees from broader process/compliance claims.

