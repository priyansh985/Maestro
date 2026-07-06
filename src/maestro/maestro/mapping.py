"""Mapping agentic agent modules to MAESTRO layers (Sec 4.2 Table 2).

Used by :mod:`maestro.experiments.runner` to emit Table 2 + Table 4 from
``configs/threats.yaml``.
"""
from __future__ import annotations

from typing import Dict, List

from .layers import LAYERS, LayerInfo
from .threats import Threat


def layer_name(code: str) -> str:
    """Translate L1 -> 'Foundation Models' (Sec 4.1)."""
    for li in LAYERS:
        if li.code == code:
            return li.name
    return code


def threat_to_layers(threats: List[Threat]) -> List[Dict[str, object]]:
    """Render rows identical to Table 2 of Sec 4.2."""
    rows: List[Dict[str, object]] = []
    for t in threats:
        rows.append({
            "Threat": f"{t.id}. {t.name}",
            "Primary Layer": f"{t.primary_layer} - {layer_name(t.primary_layer)}",
            "Cross-Layer Impact": ", ".join(t.cross_layers),
            "Brief Description": t.table1_example or "",
        })
    return rows


def threat_risk_matrix(threats: List[Threat]) -> List[Dict[str, object]]:
    """Render Table 4 of Sec 4.3.2."""
    rows: List[Dict[str, object]] = []
    for t in threats:
        rows.append({
            "Threat": f"{t.id}. {t.name}",
            "Primary Layer (MAESTRO)": t.primary_layer,
            "Cross-layer Impact": ", ".join(t.cross_layers),
            "Likelihood (P)": t.likelihood,
            "Impact (I)": t.impact,
            "Exploitability (E)": t.exploitability,
            "Risk Score": t.risk_score,
        })
    return rows
