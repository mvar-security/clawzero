# Test Authoring Guide

This is the enforcement-strength standard for all new ClawZero tests.

## Non-Negotiable Standard

Every test must enforce behavior, not just execution.

- No weak assertions like only `is not None`, existence-only checks, or broad `in` checks when exact behavior is known.
- No tolerance paths that silently accept both `allow` and `block` unless the contract explicitly allows both and each branch has strict assertions.
- No assumptions about engine behavior. Assertions must match documented runtime contracts and current policy semantics.

## Required Assertions by Path

### Block Path

Use `pytest.raises(ExecutionBlocked)` and assert:

- `decision.decision == "block"`
- `decision.sink_type == expected_sink`
- `decision.reason_code == expected_reason` (or documented bounded set only where contract requires)

### Allow / Annotate Path

Assert all of:

- Returned result semantics (exact expected payload/shape when deterministic)
- Witness sink, decision, and reason code
- Provenance contract fields when applicable (`taint_level`, markers, source chain)

## Session / Chain Tests

For multi-step/session tests, assert:

- Chain detections include expected pattern(s)
- Detection evidence references real request IDs from the executed chain
- Threshold-sensitive behavior is validated against profile thresholds
- Session report counts and persisted log contents match executed calls

## Witness Assertions

When a test depends on witness artifacts, assert:

- witness exists and is a dict
- witness request linkage (`request_id`)
- decision/sink/reason match expected enforcement outcome
- provenance fields are validated against engine normalization rules

## Generated Test Files

Generated suites are held to the same bar as handwritten suites.

- No exception-assertion no-ops
- No count-inflation-only assertions
- Same strict enforcement/result/witness/session checks as non-generated tests

## Review Checklist (PR Gate)

Before merge, reviewers should verify:

- Weak assertion patterns are absent
- Enforcement path(s) are explicitly required by assertions
- Reason codes and sinks are validated, not implied
- Tests are grounded in current contracts, not aspirational behavior
- Local targeted run and CI are both green

## Useful Contract Anchors

- `tests/policy_matrix_data.py`
- `tests/test_policy_matrix_generated.py`
- `tests/runtime/test_engine_parity_contract.py`
- `tests/test_witness_integrity_matrix.py`
