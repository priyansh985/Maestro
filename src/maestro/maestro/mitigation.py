"""Defense-in-depth mitigation registry (Sec 5.1-5.3, Figure 4).

Maps each MAESTRO layer to a list of mitigation controls. The runtime toggles
to enable/disable each control live in ``configs/default.yaml`` under
``mitigation:`` so the reproduction can be replayed under defense-on vs.
defense-off conditions.
"""
from __future__ import annotations

from dataclasses import dataclass

from .layers import LAYERS


@dataclass
class Mitigation:
    """Sec 5 mitigation catalogue."""
    layer: str
    control: str
    detail: str


@dataclass
class PyObject:
    pass


MITIGATIONS: dict[str, list[Mitigation]] = {
    "L1": [
        Mitigation("L1", "Guardrails + fine-tuning constraints",
                   "Filter prompt/response to block unsafe reasoning chains (Sec 5.3 L1)"),
        Mitigation("L1", "Output validators",
                   "Range-check LLM outputs before passing to downstream modules (Sec 5.1)"),
    ],
    "L2": [
        Mitigation("L2", "Memory isolation",
                   "Read-only/sandbox history store (Sec 5.3 L2);tamper-proof logs"),
        Mitigation("L2", "Data sanitization",
                   "Sanitize telemetry + KB before reasoning (Sec 5.1)"),
    ],
    "L3": [
        Mitigation("L3", "Planner validation",
                   "Pre-execution check of plan steps + decision-path limits (Sec 5.3 L3)"),
        Mitigation("L3", "Capability-based access control",
                   "Restrict tools by capability, not identity (Sec 5.1)"),
    ],
    "L4": [
        Mitigation("L4", "API rate limits",
                   "Token-bucket-limited tool calls to bound resource exhaustion (Sec 5.1)"),
        Mitigation("L4", "Container sandbox",
                   "Least-privilege containerized execution (Sec 5.3 L4)"),
    ],
    "L5": [
        Mitigation("L5", "Real-time anomaly detection",
                   "Threshold + ML monitoring of CPU/mem/latency drift (Sec 5.2)"),
        Mitigation("L5", "Rollback / recovery",
                   "Restore last safe-policy checkpoint on anomaly (Sec 5.2)"),
        Mitigation("L5", "Forensic logging",
                   "Tamper-proof append-only audit of inputs/reasoning/API/out (Sec 5.2)"),
    ],
    "L6": [
        Mitigation("L6", "Zero-trust auth",
                   "Per-call mutual-TLS + scoped tokens (Sec 5.1, 5.3 L6)"),
        Mitigation("L6", "Audit trail",
                   "Compliance audit + explainability logging (Sec 5.3 L6)"),
    ],
    "L7": [
        Mitigation("L7", "Trust models for cooperative agents",
                   "Limit influence of unverified agents (Sec 5.3 L7)"),
        Mitigation("L7", "Operator dashboards",
                   "Human-in-the-loop overrides (Sec 5.3 L7)"),
    ],
}


def defenses_for_layer(code: str) -> list[Mitigation]:
    return MITIGATIONS.get(code, [])


def all_defenses() -> dict[str, list[Mitigation]]:
    return {li.code: MITIGATIONS.get(li.code, []) for li in LAYERS}
