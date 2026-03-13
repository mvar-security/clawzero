# Witness Artifacts

Every evaluated request emits a witness artifact with canonical fields:

- `timestamp`
- `agent_runtime`
- `sink_type`
- `target`
- `decision`
- `reason_code`
- `policy_id`
- `engine`
- `provenance` (`source`, `taint_level`, `source_chain`, `taint_markers`)
- `adapter`
- `witness_signature`

Witnesses provide auditable evidence of deterministic enforcement decisions.
