"""
ClawZero - Execution Firewall for AI Agents.

Deterministic execution boundary between model output and tool execution.
"""

__version__ = "0.2.0"
__author__ = "MVAR Security"
__license__ = "Apache-2.0"

from clawzero.contracts import ActionDecision, ActionRequest, InputClass
from clawzero.adapters import (
    OpenClawAdapter,
    LangChainAdapter,
    protect_langchain_tool,
    wrap_langchain_tool,
    CrewAIAdapter,
    protect_crewai_tool,
    AutoGenAdapter,
    protect_autogen_function,
    MCPAdapter,
    protect_mcp_call,
    infer_mcp_sink,
)
from clawzero.exceptions import (
    ClawZeroConfigError,
    ClawZeroError,
    ClawZeroRuntimeError,
    ExecutionBlocked,
    UnsupportedFrameworkError,
)
from clawzero.protect import protect
from clawzero.protect_agent import protect_agent
from clawzero.benchmark import run_benchmark
from clawzero.runtime import MVARRuntime
from clawzero.doctor import run_openclaw_doctor, format_openclaw_doctor
from clawzero.sarif import export_sarif
from clawzero.witness import (
    WitnessGenerator,
    generate_witness,
    get_witness_generator,
    set_witness_output_dir,
)
from clawzero.witnesses.verify import (
    verify_witness_file,
    verify_witness_chain,
)

__all__ = [
    # Core API
    "protect",
    "protect_agent",
    "run_benchmark",
    "MVARRuntime",
    "OpenClawAdapter",
    "LangChainAdapter",
    "protect_langchain_tool",
    "wrap_langchain_tool",
    "CrewAIAdapter",
    "protect_crewai_tool",
    "AutoGenAdapter",
    "protect_autogen_function",
    "MCPAdapter",
    "protect_mcp_call",
    "infer_mcp_sink",
    # Contracts
    "ActionRequest",
    "ActionDecision",
    "InputClass",
    # Exceptions
    "ExecutionBlocked",
    "ClawZeroError",
    "ClawZeroConfigError",
    "ClawZeroRuntimeError",
    "UnsupportedFrameworkError",
    # Witness generation/validation
    "WitnessGenerator",
    "generate_witness",
    "get_witness_generator",
    "set_witness_output_dir",
    "verify_witness_file",
    "verify_witness_chain",
    # Doctor/reporting
    "run_openclaw_doctor",
    "format_openclaw_doctor",
    "export_sarif",
    # Adapters (optional import)
    "adapters",
]
