"""REST API that drives the *real* control plane behind the web control panel.

Every endpoint here operates the actual framework — not a mock. Submitting an
alert runs it through a live :class:`~maestro.platform.AgentPlatform` (reason →
propose → the enforcement point authorizes/executes/records); the ledger view is
the real hash-chained :class:`~maestro.security.ledger.Ledger`; the controls
view is the honest truth audit; the perimeter tester calls the real
:class:`~maestro.security.perimeter.DualLLMPerimeter`. The control panel is thin;
the security properties live in the framework and are exercised through it.

State is process-scoped and **partitioned by tenant** (CTRL-L4-08): there is one
live ``AgentPlatform`` + ledger + memory per tenant, created lazily and routed to
by the authenticated principal's tenant claim. Within a tenant the ledger,
memory, budget, and circuit breaker accumulate across requests the way an
operator would see them; across tenants the isolation is structural — a principal
for tenant A reaches a different object graph than tenant B, so there is no
shared table to leak through and no per-call scope argument to forget. (Postgres
row-level security is the single-database variant of the same guarantee, and
remains the documented production seam.)
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends
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
from .auth import (
    Principal,
    enforce_rate_limit,
    require_admin,
    require_operator,
    require_viewer,
)

# Zero-trust boundary (CTRL-L4-03): every control-plane route requires at least a
# VIEWER principal and is rate-limited per principal (router-level dependencies);
# mutating routes raise the bar to OPERATOR and the destructive /reset to ADMIN
# (per-route dependencies below).
router = APIRouter(
    prefix="/api",
    tags=["control-plane"],
    dependencies=[Depends(require_viewer), Depends(enforce_rate_limit)],
)

#: The critique panel's fixed rubric (anchored dimensions, not "is it good?").
_CRITIQUE_RUBRIC: tuple[RubricCriterion, ...] = (
    RubricCriterion("faithfulness", "Every claim is supported by the grounding."),
    RubricCriterion("actionability", "The answer states a concrete next step."),
)


# --------------------------------------------------------------------------- #
# Process-scoped live state, partitioned by tenant (CTRL-L4-08).
# --------------------------------------------------------------------------- #
class _ControlPlane:
    """One tenant's live platform + stateless helpers the panel drives.

    Every ``AgentPlatform`` here is bound to ``tenant`` (its memory scope is
    ``(tenant, agent)``), so its ledger/memory/decisions belong to exactly one
    tenant and cannot be reached by another.
    """

    def __init__(self, tenant: str) -> None:
        self.tenant = tenant
        self.perimeter = DualLLMPerimeter()
        self._threats = load_threats()
        self.reset(shadow=False)

    def reset(self, *, shadow: bool) -> None:
        """Rebuild the platform from scratch (clears ledger/memory/budget/breaker)."""
        self.platform = AgentPlatform(tenant=self.tenant, shadow=shadow)
        self.shadow = shadow

    def critique_engine(self) -> HMDCEngine:
        """A cross-family HMDC engine for the critique panel (offline judges)."""
        return HMDCEngine([RubricJudge("alpha"), RubricJudge("beta")])


class _TenantPlanes:
    """Registry of per-tenant control planes — the structural isolation boundary.

    ``for_tenant`` lazily creates and returns the caller-tenant's isolated plane;
    no method exposes another tenant's plane, so routing through this registry is
    the *only* way an endpoint touches live state, and it is impossible to touch
    the wrong tenant's.
    """

    def __init__(self) -> None:
        self._planes: dict[str, _ControlPlane] = {}

    def for_tenant(self, tenant: str) -> _ControlPlane:
        plane = self._planes.get(tenant)
        if plane is None:
            plane = _ControlPlane(tenant)
            self._planes[tenant] = plane
        return plane

    def tenants(self) -> list[str]:
        return sorted(self._planes)

    def clear(self) -> None:
        """Drop all tenant planes (used by tests for a clean slate)."""
        self._planes.clear()


_PLANES = _TenantPlanes()


# --------------------------------------------------------------------------- #
# Tenant-scoped plane resolvers: the single choke point. Each authenticates at
# its privilege tier AND returns the principal's own isolated plane, so no
# endpoint ever names a tenant or reaches a shared global.
# --------------------------------------------------------------------------- #
def viewer_plane(principal: Principal = Depends(require_viewer)) -> _ControlPlane:
    return _PLANES.for_tenant(principal.tenant)


def operator_plane(principal: Principal = Depends(require_operator)) -> _ControlPlane:
    return _PLANES.for_tenant(principal.tenant)


def admin_plane(principal: Principal = Depends(require_admin)) -> _ControlPlane:
    return _PLANES.for_tenant(principal.tenant)


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
def state(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """A one-screen snapshot: mode, kill-switch, blast radius, ledger depth."""
    platform = plane.platform
    return {
        "tenant": plane.tenant,
        "shadow": platform.shadow,
        "halted": platform.pep.halted,
        "blast_radius": platform.blast_radius().as_dict(),
        "ledger_events": len(platform.ledger),
        "ledger_intact": platform.ledger.verify_chain() == -1,
    }


@router.get("/blast-radius")
def blast_radius(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """The agent's bounded reach — legible on one screen (blueprint §2)."""
    return plane.platform.blast_radius().as_dict()


@router.get("/ledger")
def ledger(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """The tamper-evident, hash-chained audit ledger + an integrity check."""
    lg = plane.platform.ledger
    first_broken = lg.verify_chain()  # -1 if intact, else index of first tampered event
    return {
        "events": [asdict(e) for e in lg.events],
        "count": len(lg),
        "first_broken_index": first_broken,
        "intact": first_broken == -1,
        "head_hash": lg.head_hash,
    }


@router.get("/memory")
def memory(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """Scoped episodic memory, including quarantined (untrusted) records."""
    store = plane.platform.memory
    scope = plane.platform.scope
    records = store.recall(scope, include_untrusted=True)
    return {
        "scope": scope.key,
        "records": [r.as_dict() for r in records],
        "count": len(records),
    }


@router.get("/metrics")
def metrics(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """Operational metrics derived from the ledger (not self-reported counters)."""
    return compute_metrics(plane.platform.ledger)


# --------------------------------------------------------------------------- #
# Action endpoints.
# --------------------------------------------------------------------------- #
def _parse_class(name: str) -> AlertClass:
    try:
        return AlertClass(name.lower())
    except ValueError:
        return AlertClass.ANOMALY


@router.post("/alert")
def submit_alert(
    body: AlertIn, plane: _ControlPlane = Depends(operator_plane)
) -> dict[str, Any]:
    """Run one alert through the live loop and return the decision card."""
    import time

    cls = _parse_class(body.cls)
    detail = body.detail or f"operator-injected {cls.value} alert"
    alert = Alert(ts=time.time(), cls=cls, severity=body.severity, detail=detail)
    result = plane.platform.handle_alert(alert)
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
def perimeter(
    body: PerimeterIn, plane: _ControlPlane = Depends(operator_plane)
) -> dict[str, Any]:
    """Rule on untrusted external content through the dual-LLM perimeter."""
    return plane.perimeter.ingest(body.content, source=body.source).as_dict()


@router.post("/critique")
def critique(
    body: CritiqueIn, plane: _ControlPlane = Depends(operator_plane)
) -> dict[str, Any]:
    """Run a candidate output through the HMDC pipeline (offline judges)."""
    engine = plane.critique_engine()
    spec = CritiqueSpec(
        intent=body.intent,
        grounding=tuple(body.grounding),
        rubric=_CRITIQUE_RUBRIC,
    )
    candidate = Candidate(text=body.text, family=body.family)
    return engine.critique(candidate, spec).as_dict()


@router.post("/halt")
def halt(plane: _ControlPlane = Depends(operator_plane)) -> dict[str, Any]:
    """Trip the kill switch — deny all further actions (this tenant's plane)."""
    plane.platform.halt()
    return {"halted": True}


@router.post("/resume")
def resume(plane: _ControlPlane = Depends(operator_plane)) -> dict[str, Any]:
    plane.platform.resume()
    return {"halted": False}


@router.post("/reset")
def reset(body: ResetIn, plane: _ControlPlane = Depends(admin_plane)) -> dict[str, Any]:
    """Rebuild this tenant's platform (clears its ledger/memory); optionally shadow.

    Structurally scoped to the caller's tenant: an admin of tenant A cannot reset
    tenant B's plane because ``admin_plane`` only ever yields A's.
    """
    plane.reset(shadow=body.shadow)
    return {
        "tenant": plane.tenant,
        "shadow": plane.shadow,
        "ledger_events": len(plane.platform.ledger),
    }
