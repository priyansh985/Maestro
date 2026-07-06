"""MAESTRO 7-layer architecture (Sec 4.1 of arXiv:2508.10043, Figure 3).

The agent architecture maps cleanly onto seven layers L1..L7 (Sec 4.1):
  L1 Foundation Models     -> Python dataclasses
  L2 Data Operations          -> memory + telemetry pipelines
  L3 Agent Frameworks         -> planner / param-tuning logic
  L4 Deployment & Infrastructure -> FastAPI + WebSocket containers
  L5 Evaluation & Observability -> metrics + dashboards
  L6 Security and Compliance   -> auth + audit
  L7 Agent Ecosystem          -> operator dashboard + upstream agents

This module is a pure data declaration with no external dependencies so unit
tests can validate the layer set without spinning up the server.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


class Layer(str, Enum):
    """Implement Sec 4.1 MAESTRO layer definitions."""

    L1_FOUNDATION = "L1"
    L2_DATA = "L2"
    L3_AGENT = "L3"
    L4_INFRA = "L4"
    L5_EVAL = "L5"
    L6_SECURITY = "L6"
    L7_ECOSYSTEM = "L7"


@dataclass(frozen=True)
class LayerInfo:
    code: str
    name: str            # Sec 4.1 name
    role: str            # Sec 4.1 description (paraphrased)

    @classmethod
    def all_layers(cls) -> Tuple["LayerInfo", ...]:
        return LAYERS


LAYERS: Tuple[LayerInfo, ...] = (
    LayerInfo("L1", "Foundation Models",
              "Pre-trained LLM performing inference on traffic + performance anomalies (L1, Sec 4.1)"),
    LayerInfo("L2", "Data Operations",
              "Pipelines aggregating, filtering, modelling telemetry (L2, Sec 4.1)"),
    LayerInfo("L3", "Agent Frameworks",
              "Planning + execution logic invoking detection modules (L3, Sec 4.1)"),
    LayerInfo("L4", "Deployment & Infrastructure",
              "FastAPI backend, WebSocket APIs, containerised microservices (L4, Sec 4.1)"),
    LayerInfo("L5", "Evaluation & Observability",
              "Performance logs, anomaly metrics, dashboards (L5, Sec 4.1)"),
    LayerInfo("L6", "Security & Compliance",
              "Authentication, API security, audit (L6, Sec 4.1)"),
    LayerInfo("L7", "Agent Ecosystem",
              "Multi-agent + human operator interfaces (L7, Sec 4.1)"),
)


def abbrev_to_code(abbrev: str) -> str:
    """Translate shorthand like ``Foundation Models`` -> ``L1`` (Sec 4.1)."""
    m = {
        "Foundation Models": "L1",
        "Data Operations": "L2",
        "Agent Frameworks": "L3",
        "Deployment & Infrastructure": "L4",
        "Evaluation & Observability": "L5",
        "Security & Compliance": "L6",
        "Agent Ecosystem": "L7",
    }
    return m.get(abbrev, abbrev)
