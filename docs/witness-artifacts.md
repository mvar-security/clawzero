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

## Signing and Key Visibility

ClawZero signs witnesses with Ed25519 when cryptography/key material is available,
and uses `ed25519_stub` fallback only when signing cannot be initialized.

Show local signer identity:

```bash
clawzero keys show
```

Example output:

```text
ClawZero Signing Key
  Algorithm:   Ed25519
  Public key:  <base64>
  Fingerprint: <sha256-prefix>
  Key file:    ~/.clawzero/keys/witness_ed25519_private_key.pem
```

## Verification Flow

Generate proof artifacts:

```bash
clawzero prove --output-dir ./prove_witnesses
```

Verify a witness:

```bash
clawzero witness verify --file ./prove_witnesses/witness_001.json
```

Verify full chain:

```bash
clawzero witness verify-chain --dir ./prove_witnesses
```

Session-level reports:

```bash
clawzero session status <session_id>
clawzero session report <session_id> --format json
```
