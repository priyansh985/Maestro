"""Circuit breaker / loop detector (Enforcement Plane — operational safety).

Addresses the "runaway" operational risk: an agent stuck in a reasoning loop
that calls the same tool with the same arguments over and over. The rule from
the blueprint — *"if the agent calls the same tool with the same arguments N
times, halt and escalate"* — is enforced deterministically here, independent of
the model.

Repetition is keyed on a **signature** (intent + argument hash), so identical
retries collapse to one counter. A sliding window optionally forgets old
attempts so a slow, legitimate re-use much later does not trip the breaker.

This is complementary to idempotency: idempotency stops a *successful* action
from executing twice; the circuit breaker stops a *looping retry* (which never
succeeds) from running forever.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class CircuitBreaker:
    """Trips when one action signature repeats too often within a window."""

    max_repeats: int = 3
    window_seconds: float | None = None
    _history: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque), init=False)
    _tripped: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        if self.max_repeats < 1:
            raise ValueError("max_repeats must be >= 1")

    def _prune(self, sig: str, now: float) -> None:
        if self.window_seconds is None:
            return
        cutoff = now - self.window_seconds
        dq = self._history[sig]
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_and_check(self, signature: str, now: float | None = None) -> bool:
        """Record one attempt; return ``True`` if the breaker is now tripped."""
        now = now if now is not None else time.time()
        if signature in self._tripped:
            return True
        self._prune(signature, now)
        dq = self._history[signature]
        dq.append(now)
        if len(dq) >= self.max_repeats:
            self._tripped.add(signature)
            return True
        return False

    def is_tripped(self, signature: str) -> bool:
        return signature in self._tripped

    @property
    def tripped(self) -> set[str]:
        return set(self._tripped)

    def reset(self, signature: str | None = None) -> None:
        """Clear the trip for one signature, or all if ``signature`` is None."""
        if signature is None:
            self._history.clear()
            self._tripped.clear()
        else:
            self._history.pop(signature, None)
            self._tripped.discard(signature)
