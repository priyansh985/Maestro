"""REST API that drives the *real* control plane behind the web control panel.

Every endpoint here operates the actual framework — not a mock. Submitting an
alert runs it through a live :class:`~maestro.platform.AgentPlatform` (reason →
propose → the enforcement point authorizes/executes/records); the ledger view is
the real hash-chained :class:`~maestro.security.ledger.Ledger`; the controls
view is the honest truth audit; the perimeter tester calls the real
:class:`~maestro.security.perimeter.DualLLMPerimeter`. The control panel is thin;
the security properties live in the framework and are exercised through it.

State is process-scoped: one live platform instance (rebuildable via ``reset``)
so the ledger, memory, budget, and circuit breaker accumulate across requests
the way an operator would see them.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..critique import (
    Candidate,
    CritiqueSpec,
    HMDCEngine,
    RubricCriterion,
    RubricJudge,
)
from ..maestro.layers import LAYERS
from ..maestro.mapping import threat_risk_matrix
from ..maestro.threats import load_threats
from ..platform import AgentPlatform
from ..security.control_status import to_report
from ..security.metrics import compute_metrics
from ..security.perimeter import DualLLMPerimeter
from ..telemetry.detection import Alert, AlertClass

router = APIRouter(prefix="/api", tags=["control-plane"])

#: The critique panel's fixed rubric (anchored dimensions, not "is it good?").
_CRITIQUE_RUBRIC: tuple[RubricCriterion, ...] = (
    RubricCriterion("faithfulness", "Every claim is supported by the grounding."),
    RubricCriterion("actionability", "The answer states a concrete next step."),
)


# --------------------------------------------------------------------------- #
# Process-scoped live state.
# --------------------------------------------------------------------------- #
class _ControlPlane:
    """Holds the single live platform + stateless helpers the panel drives."""

    def __init__(self) -> None:
        self.perimeter = DualLLMPerimeter()
        self._threats = load_threats()
        self.reset(shadow=False)

    def reset(self, *, shadow: bool) -> None:
        """Rebuild the platform from scratch (clears ledger/memory/budget/breaker)."""
        self.platform = AgentPlatform(shadow=shadow)
        self.shadow = shadow

    def critique_engine(self) -> HMDCEngine:
        """A cross-family HMDC engine for the critique panel (offline judges)."""
        return HMDCEngine([RubricJudge("alpha"), RubricJudge("beta")])


_PLANE = _ControlPlane()


# --------------------------------------------------------------------------- #
# Request models.
# --------------------------------------------------------------------------- #
class AlertIn(BaseModel):
    cls: str = Field("dos", description="alert class: normal|dos|port_scan|bruteforce|anomaly")
    severity: float = Field(0.9, ge=0.0, le=1.0)
    detail: str = ""


class PerimeterIn(BaseModel):
    content: str
    source: str = "operator:paste"


class CritiqueIn(BaseModel):
    text: str
    intent: str = "Summarize the security finding and recommend one action."
    grounding: list[str] = Field(default_factory=list)
    family: str = "candidate"


class ResetIn(BaseModel):
    shadow: bool = False


# --------------------------------------------------------------------------- #
# Read endpoints.
# --------------------------------------------------------------------------- #
@router.get("/controls")
def controls() -> dict[str, Any]:
    """The truth audit: every control on the declared→verified ladder + coverage."""
    return to_report()


@router.get("/layers")
def layers() -> dict[str, Any]:
    """The MAESTRO 7-layer model and the threat-risk matrix (Table 4)."""
    threats = load_threats()
    return {
        "layers": [asdict(layer) for layer in LAYERS],
        "matrix": threat_risk_matrix(threats),
        "threats": len(threats),
    }


@router.get("/state")
def state() -> dict[str, Any]:
    """A one-screen snapshot: mode, kill-switch, blast radius, ledger depth."""
    platform = _PLANE.platform
    return {
        "shadow": platform.shadow,
        "halted": platform.pep.halted,
        "blast_radius": platform.blast_radius().as_dict(),
        "ledger_events": len(platform.ledger),
        "ledger_intact": platform.ledger.verify_chain() == -1,
    }


@router.get("/blast-radius")
def blast_radius() -> dict[str, Any]:
    """The agent's bounded reach — legible on one screen (blueprint §2)."""
    return _PLANE.platform.blast_radius().as_dict()


@router.get("/ledger")
def ledger() -> dict[str, Any]:
    """The tamper-evident, hash-chained audit ledger + an integrity check."""
    lg = _PLANE.platform.ledger
    first_broken = lg.verify_chain()  # -1 if intact, else index of first tampered event
    return {
        "events": [asdict(e) for e in lg.events],
        "count": len(lg),
        "first_broken_index": first_broken,
        "intact": first_broken == -1,
        "head_hash": lg.head_hash,
    }


@router.get("/memory")
def memory() -> dict[str, Any]:
    """Scoped episodic memory, including quarantined (untrusted) records."""
    store = _PLANE.platform.memory
    scope = _PLANE.platform.scope
    records = store.recall(scope, include_untrusted=True)
    return {
        "scope": scope.key,
        "records": [r.as_dict() for r in records],
        "count": len(records),
    }


@router.get("/metrics")
def metrics() -> dict[str, Any]:
    """Operational metrics derived from the ledger (not self-reported counters)."""
    return compute_metrics(_PLANE.platform.ledger)


# --------------------------------------------------------------------------- #
# Action endpoints.
# --------------------------------------------------------------------------- #
def _parse_class(name: str) -> AlertClass:
    try:
        return AlertClass(name.lower())
    except ValueError:
        return AlertClass.ANOMALY


@router.post("/alert")
def submit_alert(body: AlertIn) -> dict[str, Any]:
    """Run one alert through the live loop and return the decision card."""
    import time

    cls = _parse_class(body.cls)
    detail = body.detail or f"operator-injected {cls.value} alert"
    alert = Alert(ts=time.time(), cls=cls, severity=body.severity, detail=detail)
    result = _PLANE.platform.handle_alert(alert)
    return {
        "alert_class": result.alert_class,
        "proposed_action": result.proposed_action,
        "allowed": result.allowed,
        "decision": result.decision,
        "reason": result.reason,
        "shadowed": result.shadowed,
        "decision_card": result.decision_card,
    }


@router.post("/perimeter")
def perimeter(body: PerimeterIn) -> dict[str, Any]:
    """Rule on untrusted external content through the dual-LLM perimeter."""
    return _PLANE.perimeter.ingest(body.content, source=body.source).as_dict()


@router.post("/critique")
def critique(body: CritiqueIn) -> dict[str, Any]:
    """Run a candidate output through the HMDC pipeline (offline judges)."""
    engine = _PLANE.critique_engine()
    spec = CritiqueSpec(
        intent=body.intent,
        grounding=tuple(body.grounding),
        rubric=_CRITIQUE_RUBRIC,
    )
    candidate = Candidate(text=body.text, family=body.family)
    return engine.critique(candidate, spec).as_dict()


@router.post("/halt")
def halt() -> dict[str, Any]:
    """Trip the kill switch — deny all further actions."""
    _PLANE.platform.halt()
    return {"halted": True}


@router.post("/resume")
def resume() -> dict[str, Any]:
    _PLANE.platform.resume()
    return {"halted": False}


@router.post("/reset")
def reset(body: ResetIn) -> dict[str, Any]:
    """Rebuild the platform (clears ledger/memory); optionally in shadow mode."""
    _PLANE.reset(shadow=body.shadow)
    return {"shadow": _PLANE.shadow, "ledger_events": len(_PLANE.platform.ledger)}
