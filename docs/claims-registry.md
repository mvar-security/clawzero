# Claims Registry

Source of truth for externally-visible claims.

Hard rule: if a claim is not mapped to a passing CI test, do not use it in
README/site/HN copy.

| Claim | Test | CI Status |
|---|---|---|
| OpenClaw compare demo blocks untrusted shell sink | `tests/test_claims.py::test_untrusted_shell_exec_blocks` | PASS |
| Credential sink blocks in protected path | `tests/test_claims.py::test_credentials_access_blocks` | PASS |
| 50-vector attack pack blocks payloads | `tests/attack_pack/` | PASS |
| Witness artifacts generated and schema-valid | `tests/test_witness_trust.py` | PASS |
| Witness signing supports Ed25519 with fallback | `tests/test_witness_signing.py` | PASS |
| Session taint continuity detection | `tests/test_chain_patterns.py::test_taint_continuity_detects_with_fragmented_sources` | PASS |
| Chain detector resists source-ID fragmentation evasion | `tests/test_chain_patterns.py::test_same_source_burst_not_required_for_taint_continuity` | PASS |
| Session escalation auto-upgrades profile | `tests/test_session_runtime.py::test_profile_auto_escalates_balanced_to_strict` | PASS |
| Session isolation (no cross-session taint bleed) | `tests/test_session_runtime.py::test_cross_session_isolation` | PASS |
| Engine supports optional session enrichment path | `tests/test_session_runtime.py::test_engine_evaluate_with_session_enriches_decision` | PASS |
| `clawzero keys show` exposes signer identity | `tests/test_cli_session_wrap.py::test_keys_show_prints_public_key` | PASS |
| `clawzero wrap` blocks pre-exec on policy violation | `tests/test_cli_session_wrap.py::test_wrap_block_path_does_not_execute_subprocess` | PASS |
| `clawzero wrap` executes allowed command path | `tests/test_cli_session_wrap.py::test_wrap_allow_path_executes_subprocess` | PASS |
| `clawzero prove` install-to-proof flow remains working | `tests/test_doctor_cli.py::test_doctor_output_when_secure` + `tests/test_phase4_cli.py` | PASS |

## Messaging Guardrails

- Use: "process/tool boundary interception" for `wrap` v1.
- Do not use: "syscall interception" unless implementation/test coverage exists.
- Use: "materially raises exploit cost for multi-step chains."
- Do not use absolute claims like "uncircumventable."
