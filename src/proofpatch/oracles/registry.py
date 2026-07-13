"""Closed registry for deterministic Phase 3 oracle implementations."""

from proofpatch.errors import OracleError
from proofpatch.oracles.base import Oracle
from proofpatch.oracles.command import CommandOracle


class OracleRegistry:
    """Resolve only explicitly registered oracle types."""

    def __init__(self) -> None:
        command = CommandOracle()
        self._oracles: dict[str, Oracle] = {command.type_name: command}

    def get(self, type_name: str) -> Oracle:
        try:
            return self._oracles[type_name]
        except KeyError as error:
            raise OracleError(f"Unsupported oracle type: {type_name}") from error
