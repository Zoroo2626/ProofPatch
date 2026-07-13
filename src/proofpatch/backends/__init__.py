"""Protected and observation execution backend interfaces."""

from proofpatch.backends.base import ExecutionBackend
from proofpatch.backends.docker import DockerBackend

__all__ = ["DockerBackend", "ExecutionBackend"]
