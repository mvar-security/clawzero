# Integration Quickstarts

Verified quickstarts for each framework adapter.

## OpenClaw

Native (ClawZero):

```bash
pip install clawzero==0.2.0
clawzero doctor openclaw
clawzero demo openclaw --mode compare --scenario shell
```

Via MVAR (runtime direct):

```python
from mvar.governor import ExecutionGovernor

governor = ExecutionGovernor(policy_profile="prod_locked")
decision = governor.evaluate(
    sink_type="shell.exec",
    integrity="UNTRUSTED",
    target="bash",
)
print(decision.decision)
```

Smoke test:

```bash
clawzero demo openclaw --mode compare --scenario credentials
```

## LangChain

Native (ClawZero):

```python
from clawzero.adapters.langchain import protect_langchain_tool

safe_tool = protect_langchain_tool(
    my_langchain_tool,
    sink="filesystem.read",
    profile="prod_locked",
)
```

Via MVAR (manual bridge):

```python
from mvar.governor import ExecutionGovernor

governor = ExecutionGovernor(policy_profile="prod_locked")
# Evaluate before invoking tool
```

Smoke test:

```bash
python examples/langchain_integration.py
```

## CrewAI

Native (ClawZero):

```python
from clawzero.adapters.crewai import protect_crewai_tool

safe_tool = protect_crewai_tool(my_crewai_tool, sink="http.request")
```

Via MVAR (manual bridge):

```python
from mvar.governor import ExecutionGovernor

governor = ExecutionGovernor(policy_profile="prod_locked")
```

Smoke test:

```bash
python -c "from clawzero.adapters.crewai import protect_crewai_tool; print('crewai adapter import OK')"
```

## AutoGen

Native (ClawZero):

```python
from clawzero.adapters.autogen import protect_autogen_function

safe_fn = protect_autogen_function(my_function, sink="shell.exec")
```

Via MVAR (manual bridge):

```python
from mvar.governor import ExecutionGovernor

governor = ExecutionGovernor(policy_profile="prod_locked")
```

Smoke test:

```bash
python -c "from clawzero.adapters.autogen import protect_autogen_function; print('autogen adapter import OK')"
```

## MCP (Alpha)

Native (ClawZero alpha adapter):

```python
from clawzero.adapters.mcp import MCPAdapter

adapter = MCPAdapter(profile="prod_locked")
safe_client = adapter.wrap_client(mcp_client, method_name="call_tool")
```

Via MVAR (manual bridge):

```python
from mvar.governor import ExecutionGovernor

governor = ExecutionGovernor(policy_profile="prod_locked")
```

Smoke test:

```bash
python -c "from clawzero.adapters.mcp import MCPAdapter; print('mcp adapter import OK')"
```
