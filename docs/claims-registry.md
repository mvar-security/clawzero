# Claims Registry

Single source of truth for public messaging claims.

## Verified

| Claim | Status | Evidence |
|---|---|---|
| `clawzero==0.2.0` install path works | Verified | `pip install clawzero==0.2.0` + `clawzero doctor openclaw` |
| OpenClaw compare demo blocks untrusted shell sink | Verified | `clawzero demo openclaw --mode compare --scenario shell` |
| Credential scenario blocks on `credentials.access` | Verified | `clawzero demo openclaw --mode compare --scenario credentials` |
| Witness artifact generated for enforcement decisions | Verified | `demo/expected_outputs/*.json` and `clawzero witness verify` |
| Decision latency is microsecond-class (~1ms) | Verified | `VERIFIED_CLAIMS.md` benchmark output (`~1082.6us mean`) |
| Deterministic validation corpus currently 50 vectors | Verified | `tests/attack_pack/` |

## Inferred / Positioning

| Claim | Status | Notes |
|---|---|---|
| Deterministic sink enforcement reduces prompt-injection blast radius | Inferred | Architecture claim backed by demos/tests, not independent field study yet |
| Complements sandbox isolation (E2B/Modal) | Inferred | Layering argument; requires customer deployment evidence |

## Roadmap

| Claim | Status | Notes |
|---|---|---|
| `clawzero prove` one-command UX | Roadmap (in repo) | Added on `main` branch, publish in next PyPI release |
| MCP adapter | Roadmap (alpha) | `clawzero.adapters.mcp` added; requires field validation |
| Real Ed25519 signing in native witness path | Roadmap (in repo) | Added with key generation + fallback; validate in release notes |
| Adapter conformance badge program | Roadmap | Not shipped |
