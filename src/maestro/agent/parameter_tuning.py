"""Parameter tuning module (Sec 6.3 「history.json controls the param'' module」).

Hierarchical rule: capture_duration = base + alpha * num_high_severity
(assumption A8 — alpha derived from Sec 6.3 baseline of 34s for zero entries,
then attack increases proportionally to the threat level; the production
choice is ``34 + 3*n_high`` seconds per Sec 6.3 narrative).
"""
from __future__ import annotations

from dataclasses import dataclass

from .memory import AgentMemory


@dataclass
class CaptureParams:
    duration_s: float
    snap_bytes: int = 256
    rationale: str = ""


class ParameterTuning:
    """Sec 6.3 parameter tuning module ``(L3)``.

    ``alpha_s`` = seconds of extra capture per high-severity entry in history
    (assumption A8). With zero poisoned entries -> 34s baseline (Sec 6.3).
    With 20 high-severity entries -> 34 + 3*20 = 94s -> large PCAP file.
    """

    def __init__(self, memory: AgentMemory,
                 base_s: float = 34.0,
                 alpha_s: float = 3.0,
                 high_severity_threshold: float = 0.7,
                 max_duration_s: float = 300.0):
        self.memory = memory
        self.base_s = base_s
        self.alpha_s = alpha_s
        self.high_severity_threshold = high_severity_threshold
        self.max_duration_s = max_duration_s

    def tune_capture_duration(self) -> CaptureParams:
        n_high = self.memory.poisoned_count(self.high_severity_threshold)
        dur = min(self.max_duration_s, self.base_s + self.alpha_s * n_high)
        rationale = (f"{n_high} high-severity entries -> "
                     f"{dur:.1f}s (base {self.base_s:.1f}s + "
                     f"{self.alpha_s:.1f}*{n_high})")
        return CaptureParams(duration_s=dur, rationale=rationale)
