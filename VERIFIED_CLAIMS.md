# VERIFIED CLAIMS

Last verified: March 17, 2026
Release target: clawzero==0.1.4

Every claim below has a reproducible command and expected output.

## Claim: Real Ed25519 witness signatures are active
Status: VERIFIED
Test: `pytest -q tests/test_release_contract.py::test_release_witness_contract_uses_mvar_fields`
CLI: `clawzero doctor openclaw`
Expected: `Witness signer:  Ed25519 (QSEAL) ✓`

## Claim: Witness artifacts are hash-chained and tamper-evident
Status: VERIFIED
Test: `pytest -q tests/test_witness_trust.py -k "chain_fields_present or chain_links_correctly or chain_break_detected"`
CLI: `clawzero witness verify-chain --dir ./witnesses`
Expected: `CHAIN VALID (N witnesses)`

## Claim: Witness signatures verify on generated artifacts
Status: VERIFIED
Test: `pytest -q tests/test_witness_trust.py -k "tamper_detected_by_verify"`
CLI: `clawzero witness verify --file ./witnesses/witness_001.json`
Expected: `VALID`

## Claim: OpenClaw compare demo blocks critical-shell execution
Status: VERIFIED
Test: `pytest -q tests/test_claims.py -k test_shell_injection_blocked`
CLI: `clawzero demo openclaw --mode compare --scenario shell`
Expected: `RESULT: ATTACK BLOCKED ✓`

## Claim: Installed runtime resolves to mvar-security engine
Status: VERIFIED
Test: `pytest -q tests/test_release_contract.py::test_release_witness_contract_uses_mvar_fields`
CLI: `clawzero doctor openclaw`
Expected: `Runtime......... OK (mvar-security 1.4.3)`

## Claim: Policy attribution is sourced from mvar-security
Status: VERIFIED
Test: `pytest -q tests/test_release_contract.py::test_release_witness_contract_uses_mvar_fields`
CLI: `clawzero demo openclaw --mode compare --scenario shell`
Expected: `Policy:  mvar-security.v1.4.3`

## Claim: LangChain adapter blocks untrusted shell path
Status: VERIFIED
Test: `pytest -q tests/test_langchain_adapter.py -k test_langchain_tool_blocks_shell_exec`
CLI: `python examples/langchain_integration.py`
Expected: shell path blocked; safe path allowed

## Claim: SARIF export produces valid report payload
Status: VERIFIED
Test: `pytest -q tests/test_sarif_export.py`
CLI: `clawzero report sarif --input ./witnesses --output ./results.sarif`
Expected: valid SARIF document with mapped decisions

## Claim: CEC (3-leg condition) is detected and recorded
Status: VERIFIED
Test: `pytest -q tests/test_phase3_controls.py -k "cec_triggered_all_three_legs or cec_warn_adds_to_witness or cec_enforce_escalates_profile"`
CLI: `clawzero audit decision --profile dev_balanced --sink-type http.request --target https://attacker.example/exfil --source external_document --taint-level untrusted --cec-enforce`
Expected: witness includes `cec_status` and escalation metadata when enforced

## Claim: Execution replay and explain are deterministic and readable
Status: VERIFIED
Test: `pytest -q tests/test_phase4_cli.py -k "witness_explain_output or replay_orders_and_summarizes"`
CLI: `clawzero witness explain ./witnesses/witness_001.json && clawzero replay --session ./witnesses`
Expected: structured explanation and ordered session summary
