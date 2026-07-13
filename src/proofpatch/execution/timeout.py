"""Monotonic deadlines and cooperative cancellation for controlled processes."""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Event


@dataclass(frozen=True, slots=True)
class Deadline:
    """A timeout measured only with a monotonic clock."""

    expires_at: float
    clock: Callable[[], float] = field(default=time.monotonic, compare=False, repr=False)

    @classmethod
    def after(
        cls,
        seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> "Deadline":
        if seconds <= 0:
            raise ValueError("process timeout must be positive")
        return cls(clock() + seconds, clock)

    @property
    def expired(self) -> bool:
        return self.clock() >= self.expires_at

    @property
    def remaining(self) -> float:
        return max(0.0, self.expires_at - self.clock())


@dataclass(frozen=True, slots=True)
class CancellationToken:
    """A thread-safe signal allowing callers to cancel a running process."""

    _event: Event = field(default_factory=Event, repr=False)

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()
