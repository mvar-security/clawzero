# Attack Demo

> ⚠️ Defensive demonstration
>
> The attack scenarios in this page are intentionally constructed to show
> how untrusted inputs interact with execution boundaries.
>
> They are included for defensive research only.
>
> Only run these demonstrations on systems you own or are authorized to test.

The attack demo shows one input crossing two boundaries:

1. Standard OpenClaw path with no deterministic sink boundary
2. ClawZero path with MVAR enforcement in-path

This demo is included as **proof of enforcement behavior**. It is not the product center.

Run:

```bash
clawzero demo openclaw --mode compare --scenario shell
clawzero demo openclaw --mode compare --scenario credentials
clawzero demo openclaw --mode compare --scenario benign
```

The demo is intentionally deterministic and does not execute harmful subprocesses in the standard path.
