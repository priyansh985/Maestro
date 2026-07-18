"""Performance Analysis Module (Sec 3.1).

Tracks latency, jitter, bandwidth, QoS metrics in time-series form and
emits the signals the security detection module consumes (Sec 3.1 para 2).
The CPU/memory emulation mirrors what Figure 6 of the paper plots.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


@dataclass
class PerformanceSample:
    ts: float
    cpu_pct: float
    mem_pct: float
    pkt_rate_pps: float
    latency_ms: float


def _bounded(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


# Logistic load model (assumption A13). f(x) = 1 / (1 + exp(-k (x - x0))) with
# k, x0 calibrated so the Sec 6.2 DoS rate (10 kpps) saturates (~1.0 load) while
# a benign baseline (~200 pps) is ~0.0. Both cpu/mem and the TC1 telemetry-lag
# model read from this single curve so they stay mutually consistent.
_LOAD_K = 0.0025
_LOAD_X0 = 5000.0  # midpoint packet rate


def load_fraction(pkt_rate_pps: float) -> float:
    """Modeled system-load fraction in [0, 1] for a given packet rate (A13)."""
    return 1.0 / (1.0 + math.exp(-_LOAD_K * (pkt_rate_pps - _LOAD_X0)))


@dataclass
class PerformanceMonitor:
    """Implements Sec 3.1 Performance Analysis Module.

    cpu/mem are derived from packet rate with a soft saturation curve so the
    dashboard shows the same shape as Figure 6 under DoS replay.
    """
    pkt_rate_pps: float = 0.0
    cpu_pct: float = 5.0
    mem_pct: float = 30.0
    history: list[PerformanceSample] = field(default_factory=list)
    cpu_high_pct: float = 80.0
    mem_high_pct: float = 80.0
    pkt_rate_high_pps: float = 8000.0

    def update(self, pkt_rate_pps: float, t: float | None = None) -> PerformanceSample:
        """Map instantaneous packet rate to cpu/mem usage (Sec 3.1, Figure 6).

        Soft saturation f(x) = 100 / (1 + exp(-k (x - x0))) with k chosen so
        that 10kpps (Sec 6.2 dos rate) lands ~95%; baseline ~10%.
        """
        if t is None:
            t = time.time()
        self.pkt_rate_pps = pkt_rate_pps
        load = load_fraction(pkt_rate_pps)
        target_cpu = 5.0 + 95.0 * load
        target_mem = 25.0 + 70.0 * load
        # exponential smoothing -> first-order lag matches Sec 5.2 telemetry drift
        alpha = 0.3
        self.cpu_pct = (1 - alpha) * self.cpu_pct + alpha * target_cpu
        self.mem_pct = (1 - alpha) * self.mem_pct + alpha * target_mem
        latency_ms = max(5.0, 5.0 + (pkt_rate_pps / 1000.0) ** 1.2)
        s = PerformanceSample(ts=t, cpu_pct=_bounded(self.cpu_pct),
                              mem_pct=_bounded(self.mem_pct),
                              pkt_rate_pps=pkt_rate_pps, latency_ms=latency_ms)
        self.history.append(s)
        return s

    def is_anomaly(self) -> bool:
        """Boolean anomaly flag used by the Planner (Sec 3.1 Security Detection)."""
        return (self.cpu_pct >= self.cpu_high_pct or
                self.mem_pct >= self.mem_high_pct or
                self.pkt_rate_pps >= self.pkt_rate_high_pps)
