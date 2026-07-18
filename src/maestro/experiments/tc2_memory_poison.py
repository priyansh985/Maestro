"""Test Case 2 — Memory / Knowledge-Base Poisoning (Sec 6.3 TC2).

Injects 20 fake high-severity entries into ``history.json`` and verifies
that the parameter tuning module chooses a much larger capture duration,
causing a larger PCAP and resource exhaustion downstream (Sec 6.3).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..agent.memory import AgentMemory
from ..agent.parameter_tuning import ParameterTuning

logger = logging.getLogger("maestro.exp.tc2")


@dataclass
class TC2Result:
    history_path: str
    n_poisoned: int
    n_baseline_high_severity: int
    n_post_high_severity: int
    baseline_capture_duration_s: float
    post_capture_duration_s: float
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "history_path": self.history_path,
            "n_poisoned": self.n_poisoned,
            "n_baseline_high_severity": self.n_baseline_high_severity,
            "n_post_high_severity": self.n_post_high_severity,
            "baseline_capture_duration_s": self.baseline_capture_duration_s,
            "post_capture_duration_s": self.post_capture_duration_s,
            "ratio": (self.post_capture_duration_s /
                      max(1e-9, self.baseline_capture_duration_s)),
            "notes": self.notes,
        }


def run_tc2(cfg) -> TC2Result:
    """Execute Sec 6.3 TC2 — poison history, observe capture-duration inflation."""
    hist_path = str(cfg.memory_poison.history_path)
    n_inject = int(cfg.memory_poison.num_injected)
    injected_sev = float(cfg.memory_poison.injected_severity)
    base_s = float(cfg.memory_poison.expected_baseline_capture_s)
    alpha_s = float(cfg.memory_poison.severity_alpha_s)
    high_sev = float(cfg.memory_poison.high_severity_threshold)

    memory = AgentMemory(hist_path)
    memory.load()
    # The TC2 premise (Sec 6.3) is a *clean* episodic memory that yields the
    # 34 s baseline capture ("valid entries or no recordings ... e.g. 34
    # seconds"). Reset first so the measured baseline is deterministic and
    # isolated from any telemetry the agent may have logged into the shared
    # history.json during a prior experiment (e.g. TC1 alerts).
    memory.clear()
    # baseline
    n_baseline = memory.poisoned_count(high_sev)
    tuning = ParameterTuning(memory,
                             base_s=base_s, alpha_s=alpha_s,
                             high_severity_threshold=high_sev)
    baseline_cap = tuning.tune_capture_duration()

    # poison
    inserted = memory.insert_poisoned_entries(n_inject, severity=injected_sev)
    n_post = memory.poisoned_count(high_sev)
    post_cap = tuning.tune_capture_duration()
    notes: list[str] = [
        f"Inserted {inserted} fake high-severity entries "
        f"(severity={injected_sev}) -> history.json (Sec 6.3).",
        f"Tuner chose capture duration {post_cap.duration_s:.1f}s vs "
        f"baseline {baseline_cap.duration_s:.1f}s "
        "(Sec 6.3: large PCAP + slow detection).",
    ]
    if cfg.mitigation.memory_isolation:
        memory.freeze()
        notes.append("Memory isolation (Sec 5.3 L2) enabled - file frozen.")

    return TC2Result(
        history_path=hist_path,
        n_poisoned=n_inject,
        n_baseline_high_severity=n_baseline,
        n_post_high_severity=n_post,
        baseline_capture_duration_s=baseline_cap.duration_s,
        post_capture_duration_s=post_cap.duration_s,
        notes=notes,
    )
