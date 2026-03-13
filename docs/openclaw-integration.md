# OpenClaw Integration

Use `OpenClawAdapter` to enforce decisions at tool boundaries:

```python
from clawzero.adapters import OpenClawAdapter

adapter = OpenClawAdapter(profile="prod_locked")
safe_tool = adapter.wrap_tool(my_tool, sink_type="shell.exec")
```

Both wrapped-tool and event-intercept paths attach canonical provenance metadata and route through the same runtime evaluator.
