"""Witness generation package for signed enforcement artifacts."""

from clawzero.witnesses.generator import (
    WitnessGenerator,
    generate_witness,
    get_witness_generator,
    set_witness_output_dir,
)
from clawzero.witnesses.verify import (
    ChainVerificationResult,
    VerificationResult,
    verify_witness_chain,
    verify_witness_file,
    verify_witness_object,
)

__all__ = [
    "WitnessGenerator",
    "generate_witness",
    "get_witness_generator",
    "set_witness_output_dir",
    "VerificationResult",
    "ChainVerificationResult",
    "verify_witness_object",
    "verify_witness_file",
    "verify_witness_chain",
]
