"""Deterministic oracle interfaces and the Phase 3 command implementation."""

from proofpatch.oracles.base import Oracle, OracleExecutionContext, OracleExecutionResult
from proofpatch.oracles.command import CommandOracle
from proofpatch.oracles.registry import OracleRegistry

__all__ = [
    "CommandOracle",
    "Oracle",
    "OracleExecutionContext",
    "OracleExecutionResult",
    "OracleRegistry",
]
