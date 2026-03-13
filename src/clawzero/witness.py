"""Compatibility exports for witness generation."""

from clawzero.witnesses.generator import (
    WitnessGenerator,
    generate_witness,
    get_witness_generator,
    set_witness_output_dir,
)

__all__ = [
    "WitnessGenerator",
    "generate_witness",
    "get_witness_generator",
    "set_witness_output_dir",
]
