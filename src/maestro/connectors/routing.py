"""Latency-aware routing over the Provider Abstraction Layer (blueprint §6).

Given several interchangeable connectors, route each request to the one with the
best *observed* tail latency, not a static preference order. A
:class:`LatencyTracker` keeps a sliding window of per-connector samples and
exposes p50/p95; the :class:`LatencyAwareRouter` **explores** connectors it has
no data for (so a new backend gets measured) and otherwise **exploits** the
lowest-p95 healthy connector.

This is deliberately synchronous and deterministic — it selects on recorded
statistics, so it is testable without real timing. Tail-latency *hedging* (fire
a backup at the p95 mark, take the first to return) is the concurrent extension
of the same p95 signal; it belongs in an async transport and is out of scope for
this offline reference.
"""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Sequence

from .base import ChatRequest, ChatResponse, ModelConnector, ProviderUnavailableError


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile of a non-empty list."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = int(round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, rank))]


class LatencyTracker:
    """Sliding-window latency samples per connector name."""

    def __init__(self, window: int = 50) -> None:
        self._samples: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def record(self, name: str, latency_ms: float) -> None:
        self._samples[name].append(latency_ms)

    def samples(self, name: str) -> list[float]:
        return list(self._samples.get(name, ()))

    def p50(self, name: str) -> float | None:
        s = self.samples(name)
        return _percentile(s, 50.0) if s else None

    def p95(self, name: str) -> float | None:
        s = self.samples(name)
        return _percentile(s, 95.0) if s else None


class LatencyAwareRouter:
    """Selects the healthiest, lowest-tail-latency connector for each request."""

    def __init__(
        self,
        connectors: Sequence[ModelConnector],
        *,
        tracker: LatencyTracker | None = None,
    ) -> None:
        if not connectors:
            raise ValueError("LatencyAwareRouter requires at least one connector")
        self._connectors = tuple(connectors)
        self._tracker = tracker if tracker is not None else LatencyTracker()

    @property
    def tracker(self) -> LatencyTracker:
        return self._tracker

    def select(self) -> ModelConnector:
        """Pick a connector: explore any unmeasured one, else exploit lowest p95."""
        eligible = [c for c in self._connectors if c.enabled]
        if not eligible:
            raise ProviderUnavailableError("no enabled connectors to route to")

        # Exploration: a connector with no samples yet is tried first so we learn
        # its latency before ranking. Declared order breaks ties deterministically.
        for connector in eligible:
            if not self._tracker.samples(connector.name):
                return connector

        # Exploitation: lowest p95 wins (tail latency is what hurts in practice).
        return min(eligible, key=lambda c: self._tracker.p95(c.name) or float("inf"))

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Route the request and record the observed latency for future routing."""
        connector = self.select()
        response = connector.chat(request)
        self._tracker.record(connector.name, response.latency_ms)
        return response
