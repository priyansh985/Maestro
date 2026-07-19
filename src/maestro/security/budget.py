"""Autonomy budget + rate limiting (Enforcement Plane).

The critique's authorization predicate includes a ``BudgetAvailable`` conjunct
that the first enforcement cut lacked:

    Allow = DeterministicPolicyPass ∧ ValidCapability ∧ SchemaPass
            ∧ BudgetAvailable ∧ RequiredApprovalPresent

An :class:`AutonomyBudget` bounds how much an agent may do before a human must
re-authorize: total tool calls, cumulative spend, cumulative blast radius
(hosts/records affected), and a sliding-window call rate. Budgets are consumed
only for actions that actually execute; a denied action costs nothing.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


class BudgetError(Exception):
    """Raised when an action would exceed the agent's autonomy budget."""


@dataclass
class AutonomyBudget:
    """A consumable, rate-limited budget for one agent run.

    Any limit left as ``None`` is unbounded. :meth:`check` is side-effect-free
    (used to gate before execution); :meth:`consume` commits usage after a
    successful execution.
    """

    max_tool_calls: int | None = None
    max_spend: float | None = None
    max_affected: int | None = None
    window_seconds: float | None = None
    max_calls_per_window: int | None = None

    _calls: int = field(default=0, init=False)
    _spend: float = field(default=0.0, init=False)
    _affected: int = field(default=0, init=False)
    _window: deque[float] = field(default_factory=deque, init=False)

    def _prune(self, now: float) -> None:
        if self.window_seconds is None:
            return
        cutoff = now - self.window_seconds
        while self._window and self._window[0] < cutoff:
            self._window.popleft()

    def check(self, *, cost: float = 0.0, affected: int = 0, now: float | None = None) -> None:
        """Raise :class:`BudgetError` if committing this action would overrun."""
        now = now if now is not None else time.time()
        if cost < 0 or affected < 0:
            raise BudgetError("cost and affected must be non-negative")
        if self.max_tool_calls is not None and self._calls + 1 > self.max_tool_calls:
            raise BudgetError(f"tool-call budget exhausted ({self.max_tool_calls})")
        if self.max_spend is not None and self._spend + cost > self.max_spend:
            raise BudgetError(f"spend budget exceeded ({self.max_spend})")
        if self.max_affected is not None and self._affected + affected > self.max_affected:
            raise BudgetError(f"blast-radius budget exceeded ({self.max_affected})")
        if self.window_seconds is not None and self.max_calls_per_window is not None:
            self._prune(now)
            if len(self._window) + 1 > self.max_calls_per_window:
                raise BudgetError(
                    f"rate limit exceeded ({self.max_calls_per_window}/{self.window_seconds}s)")

    def consume(self, *, cost: float = 0.0, affected: int = 0, now: float | None = None) -> None:
        """Commit usage; call only after :meth:`check` passed and the action ran."""
        now = now if now is not None else time.time()
        self._calls += 1
        self._spend += cost
        self._affected += affected
        if self.window_seconds is not None:
            self._window.append(now)

    @property
    def usage(self) -> dict[str, float]:
        return {"calls": self._calls, "spend": self._spend, "affected": self._affected}
