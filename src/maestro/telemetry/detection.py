"""Security Detection Module (Sec 3.1).

Pattern recog + behaviour analysis + signature DB; runs alongside the LLM
reasoning engine (Sec 3.1 para 3). Implementations here are deterministic
so the toolchain is unit-testable without an LLM (assumption A1, A2).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .performance import PerformanceMonitor


class AlertClass(str, Enum):
    NORMAL = "normal"
    DOS = "dos"
    PORT_SCAN = "port_scan"
    BRUTEFORCE = "bruteforce"
    ANOMALY = "anomaly"


@dataclass
class Alert:
    ts: float
    cls: AlertClass
    severity: float           # 0..1 (Sec 6.2 「threshold violations」)
    detail: str = ""


@dataclass
class SecurityDetector:
    """Sec 3.1 Security Detection Module.

    Uses simple thresholds + sliding statistics. The LLM Reasoning engine is
    used in parallel for context-sensitive correlation; we stub it (L1) here.
    """
    perf: PerformanceMonitor
    alerts: list[Alert] = field(default_factory=list)
    baseline_pkt_rate: float = 200.0  # ASSUMPTION A5: typical benign rate

    def evaluate(self, pkt_rate_pps: float, t: float | None = None) -> Alert:
        import time
        if t is None:
            t = time.time()
        self.perf.update(pkt_rate_pps, t=t)
        if self.perf.pkt_rate_pps > 10 * max(1.0, self.baseline_pkt_rate):
            sev = min(1.0, self.perf.cpu_pct / 100.0)
            a = Alert(t, AlertClass.DOS, sev, "High packet flood; CPU saturated")
        elif self.perf.pkt_rate_pps > 3 * self.baseline_pkt_rate:
            sev = min(0.8, self.perf.cpu_pct / 100.0)
            a = Alert(t, AlertClass.ANOMALY, sev, "Elevated packet rate")
        elif self.perf.cpu_pct >= self.perf.cpu_high_pct:
            sev = min(0.9, self.perf.cpu_pct / 100.0)
            a = Alert(t, AlertClass.ANOMALY, sev, "CPU saturation")
        else:
            a = Alert(t, AlertClass.NORMAL, 0.1, "Within baseline envelope")
        self.alerts.append(a)
        return a
