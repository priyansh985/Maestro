"""Threat definitions (Sec 3.2 Table 1 + Sec 4.3.2 Table 4).

Loads ``configs/threats.yaml`` and produces :class:`Threat` objects whose
``risk_score`` field matches Sec 4.3 Table 4 exactly. The loader is also
verifiable by ``python -m maestro.scripts.validate_threats``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from omegaconf import DictConfig, OmegaConf

from ..config import _REPO_ROOT
from .risk_score import RiskComponents, risk_score_components


@dataclass
class Threat:
    """One row of Sec 3.2 / Sec 4.3.2."""
    id: int
    name: str
    primary_layer: str
    cross_layers: list[str]
    likelihood: str
    impact: str
    exploitability: str
    risk_score: int
    table1_name: str | None = None
    table1_example: str | None = None
    table1_layers: list[str] = field(default_factory=list)

    def components(self) -> RiskComponents:
        return RiskComponents(
            likelihood=self.likelihood,  # type: ignore[arg-type]
            impact=self.impact,           # type: ignore[arg-type]
            exploitability=self.exploitability,  # type: ignore[arg-type]
        )


def load_threats(path: str | Path | None = None) -> list[Threat]:
    """Load threats from ``configs/threats.yaml``."""
    p = Path(path) if path is not None else _REPO_ROOT / "configs" / "threats.yaml"
    cfg = cast(DictConfig, OmegaConf.load(p))
    out: list[Threat] = []
    for entry in cfg["threats"]:
        t = Threat(
            id=int(entry["id"]),
            name=str(entry["name"]),
            primary_layer=str(entry["primary_layer"]),
            cross_layers=list(entry["cross_layers"]),
            likelihood=str(entry["likelihood"]),
            impact=str(entry["impact"]),
            exploitability=str(entry["exploitability"]),
            risk_score=int(entry["risk_score"]),
            table1_name=entry.get("table1_name"),
            table1_example=entry.get("table1_example"),
            table1_layers=list(entry.get("table1_layers", [])),
        )
        expected = risk_score_components(t.components())
        if expected != t.risk_score:
            raise ValueError(
                f"Threat {t.id} ({t.name}) risk_score {t.risk_score} != {expected} "
                f"computed from P*I*E"
            )
        out.append(t)
    out.sort(key=lambda x: x.id)
    return out


def threat_by_id(threats: list[Threat], tid: int) -> Threat:
    for t in threats:
        if t.id == tid:
            return t
    raise KeyError(f"Threat #{tid} not found")
