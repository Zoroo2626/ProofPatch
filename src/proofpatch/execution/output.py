"""Thread-safe, total-budget process output capture that always keeps draining."""

from dataclasses import dataclass, field
from threading import Lock


@dataclass(slots=True)
class OutputBudget:
    """Share one exact byte budget across stdout and stderr reader threads."""

    maximum_bytes: int
    _remaining: int = field(init=False)
    _truncated: bool = field(default=False, init=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.maximum_bytes <= 0:
            raise ValueError("process output limit must be positive")
        self._remaining = self.maximum_bytes

    def retain(self, chunk: bytes) -> bytes:
        """Retain the available prefix and mark truncation while callers keep draining."""

        with self._lock:
            length = min(len(chunk), self._remaining)
            retained = chunk[:length]
            self._remaining -= length
            if length != len(chunk):
                self._truncated = True
            return retained

    @property
    def truncated(self) -> bool:
        with self._lock:
            return self._truncated
