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

import time
from dataclasses import asdict
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
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
from ..memory import MemoryTier
from ..memory.store import MemoryIsolationError, MemoryWriteDenied, memory_resource
from ..platform import AgentPlatform
from ..security.control_status import to_report
from ..security.identity import CapabilityError
from ..security.metrics import compute_metrics
from ..security.perimeter import DualLLMPerimeter
from ..security.policy_bundle import PolicyBundle
from ..telemetry.detection import Alert, AlertClass
from .agent_registry import REGISTRY
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
        self.created_at = time.time()
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

    def peek(self, tenant: str) -> _ControlPlane | None:
        """The tenant's plane if one exists — never creates (for listing)."""
        return self._planes.get(tenant)

    def tenants(self) -> list[str]:
        return sorted(self._planes)

    def clear(self) -> None:
        """Drop all tenant planes (used by tests for a clean slate)."""
        self._planes.clear()


_PLANES = _TenantPlanes()

#: Tenants under isolation (containment): tenant -> isolated_at timestamp.
_ISOLATED: dict[str, float] = {}


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


class MemoryPromoteIn(BaseModel):
    record_id: str
    capability: str = Field(
        "cap:memory:promote",
        description="the capability being asserted; the scoped token is minted "
        "server-side under the OPERATOR role and ledgered",
    )


class MemoryQuarantineIn(BaseModel):
    record_id: str


class TenantCreateIn(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9:._-]+$")
    display_name: str | None = None
    quotas: dict[str, Any] | None = None


class PolicyValidateIn(BaseModel):
    policy_yaml: str


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
    blast = plane.platform.blast_radius()
    d = blast.as_dict()
    d["holds_irreversible_capability"] = blast.holds_irreversible_capability
    return d


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
def memory(
    tier: str | None = None,
    include_untrusted: bool = True,
    limit: int = 100,
    plane: _ControlPlane = Depends(viewer_plane),
) -> dict[str, Any]:
    """Scoped memory with tier/trust/limit filters, quarantined records included."""
    store = plane.platform.memory
    scope = plane.platform.scope
    tier_filter: MemoryTier | None = None
    if tier:
        try:
            tier_filter = MemoryTier(tier.lower())
        except ValueError:
                    raise HTTPException(status_code=400, detail=f"unknown tier {tier!r}") from None
    records = store.recall(
        scope, tier=tier_filter, include_untrusted=include_untrusted,
        limit=max(1, min(limit, 1000)))
    return {
        "scope": scope.key,
        "records": [r.as_dict() for r in records],
        "count": len(records),
        "total": len(records),
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
    cls = _parse_class(body.cls)
    detail = body.detail or f"operator-injected {cls.value} alert"
    ts = time.time()
    alert = Alert(ts=ts, cls=cls, severity=body.severity, detail=detail)
    result = plane.platform.handle_alert(alert)
    return {
        "alert_id": f"{plane.platform.scope.agent}:{int(ts * 1000)}",
        "tenant": plane.tenant,
        "created_at": ts,
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
    return {"halted": True, "message": f"tenant {plane.tenant!r} plane halted (kill switch tripped)"}


@router.post("/resume")
def resume(plane: _ControlPlane = Depends(operator_plane)) -> dict[str, Any]:
    plane.platform.resume()
    return {"halted": False, "message": f"tenant {plane.tenant!r} plane resumed"}


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


# --------------------------------------------------------------------------- #
# Ledger verification and export (the tamper-evidence surface, BP11).
# --------------------------------------------------------------------------- #
@router.get("/ledger/verify")
def ledger_verify(plane: _ControlPlane = Depends(viewer_plane)) -> dict[str, Any]:
    """Re-walk the hash chain + HMACs; -1 first_broken_index means intact."""
    lg = plane.platform.ledger
    first_broken = lg.verify_chain()
    return {
        "intact": first_broken == -1,
        "events": len(lg),
        "head_hash": lg.head_hash,
        "first_broken_index": first_broken if first_broken != -1 else None,
    }


@router.get("/ledger/export")
def ledger_export(
    limit: int | None = None, plane: _ControlPlane = Depends(viewer_plane)
) -> dict[str, Any]:
    """Export ledger events (most recent last, as the chain is ordered)."""
    events = list(plane.platform.ledger.events)
    if limit is not None:
        events = events[-max(1, min(limit, 10_000)):]
    return {"events": [asdict(e) for e in events], "count": len(events)}


# --------------------------------------------------------------------------- #
# Memory management: promote (capability-gated) and quarantine (operator).
# --------------------------------------------------------------------------- #
@router.post("/memory/promote")
def promote_memory(
    body: MemoryPromoteIn,
    plane: _ControlPlane = Depends(operator_plane),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    """Promote a quarantined record to TRUSTED.

    The promotion itself is capability-gated in the store: the server mints a
    short-lived ``cap:memory:promote`` token scoped to this tenant's memory
    resource *on behalf of the authenticated OPERATOR principal* — the RBAC
    boundary is the authorization, the capability is the mechanism, and the
    promotion lands in the tenant's tamper-evident ledger with provenance.
    """
    from ..memory.store import PROMOTE_CAPABILITY
    store = plane.platform.memory
    scope = plane.platform.scope
    try:
        token = store.issuer.issue(
            subject=principal.subject,
            capability=PROMOTE_CAPABILITY,
            resource_constraint=memory_resource(scope),
            tenant=scope.tenant,
            ttl_seconds=60.0,
        )
        record = store.promote(body.record_id, scope, token=token)
    except CapabilityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except MemoryWriteDenied as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MemoryIsolationError as exc:
        raise HTTPException(
            status_code=404, detail=f"record {body.record_id!r} not found in scope") from exc
    return {"promoted": True, "record": record.as_dict()}


@router.post("/memory/quarantine")
def quarantine_memory(
    body: MemoryQuarantineIn,
    plane: _ControlPlane = Depends(operator_plane),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    """Quarantine a trusted record (demote to UNTRUSTED) — risk-reducing, so
    operator authority suffices; the demotion is ledgered and attributable."""
    store = plane.platform.memory
    scope = plane.platform.scope
    try:
        record = store.demote(body.record_id, scope, actor=principal.subject)
    except MemoryWriteDenied as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MemoryIsolationError as exc:
        raise HTTPException(
            status_code=404, detail=f"record {body.record_id!r} not found in scope") from exc
    return {"quarantined": True, "record": record.as_dict()}


# --------------------------------------------------------------------------- #
# Tenant administration (control-plane ADMIN; cross-tenant by charter).
# --------------------------------------------------------------------------- #
_TENANT_META: dict[str, dict[str, Any]] = {}


def _tenant_info(tenant_id: str) -> dict[str, Any]:
    plane = _PLANES.peek(tenant_id)
    meta = _TENANT_META.get(tenant_id, {})
    return {
        "tenant_id": tenant_id,
        "display_name": meta.get("display_name") or tenant_id,
        "created_at": plane.created_at if plane is not None else meta.get("created_at"),
        "quotas": meta.get("quotas") or {},
        "agents": len(REGISTRY.list(tenant_id)),
        "ledger_events": len(plane.platform.ledger) if plane is not None else 0,
        "isolated": tenant_id in _ISOLATED,
        "isolated_at": _ISOLATED.get(tenant_id),
    }


def _known_tenants() -> list[str]:
    return sorted(set(_PLANES.tenants()) | set(REGISTRY.tenants()) | set(_TENANT_META))


@router.get("/tenants")
def list_tenants(principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    """Every known tenant partition (admin: this is the control-plane view)."""
    tenants = [_tenant_info(t) for t in _known_tenants()]
    return {"tenants": tenants, "total": len(tenants)}


@router.post("/tenants", status_code=201)
def create_tenant(
    body: TenantCreateIn, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    """Register a new tenant partition (its plane materializes lazily)."""
    if body.tenant_id in _known_tenants():
        raise HTTPException(status_code=409, detail=f"tenant {body.tenant_id!r} already exists")
    _TENANT_META[body.tenant_id] = {
        "display_name": body.display_name,
        "quotas": body.quotas or {},
        "created_at": time.time(),
        "created_by": principal.subject,
    }
    _PLANES.for_tenant(body.tenant_id)  # materialize the isolated plane
    return _tenant_info(body.tenant_id)


@router.get("/tenants/{tenant_id}")
def get_tenant(tenant_id: str, principal: Principal = Depends(require_admin)) -> dict[str, Any]:
    if tenant_id not in _known_tenants():
        raise HTTPException(status_code=404, detail=f"tenant {tenant_id!r} not found")
    return _tenant_info(tenant_id)


@router.post("/tenants/{tenant_id}/isolate")
def isolate_tenant(
    tenant_id: str, principal: Principal = Depends(require_admin)
) -> dict[str, Any]:
    """Containment: trip the kill switch on the tenant's plane and every agent
    in its fleet. Fail-closed — all further actions in that tenant are denied
    until an operator explicitly resumes them."""
    if tenant_id not in _known_tenants():
        raise HTTPException(status_code=404, detail=f"tenant {tenant_id!r} not found")
    plane = _PLANES.peek(tenant_id)
    if plane is not None:
        plane.platform.halt()
    agents_halted = REGISTRY.halt_all(tenant_id)
    _ISOLATED[tenant_id] = time.time()
    return {
        "tenant_id": tenant_id,
        "isolated": True,
        "agents_halted": agents_halted,
        "plane_halted": plane is not None,
        "message": f"tenant {tenant_id!r} isolated: kill switches tripped",
    }


# --------------------------------------------------------------------------- #
# Policy validation (dry-run a bundle against the executor contract).
# --------------------------------------------------------------------------- #
@router.post("/policies/validate")
def validate_policy(
    body: PolicyValidateIn, plane: _ControlPlane = Depends(operator_plane)
) -> dict[str, Any]:
    """Validate a YAML policy bundle without activating it.

    Checks the executor's actual contract: ``allowed_intents`` must be a list of
    known intents (the platform rejects unknown ones at construction), ``version``
    a positive integer, ``limits`` a numeric mapping. Returns the bundle's
    content digest so the validated artifact is pinned.
    """
    from ..security.action import INTENT_REGISTRY

    errors: list[str] = []
    warnings: list[str] = []
    try:
        doc = yaml.safe_load(body.policy_yaml)
    except yaml.YAMLError as exc:
        return {"valid": False, "errors": [f"YAML parse error: {exc}"],
                "warnings": [], "digest": None}

    if not isinstance(doc, dict):
        return {"valid": False,
                "errors": ["policy document must be a YAML mapping "
                           "(allowed_intents, version, limits)"],
                "warnings": [], "digest": None}

    version = doc.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        errors.append("version must be a positive integer")

    intents = doc.get("allowed_intents")
    if intents is None:
        errors.append("allowed_intents is required (an explicit allow-list)")
        intents = []
    elif not isinstance(intents, list) or not all(isinstance(i, str) for i in intents):
        errors.append("allowed_intents must be a list of strings")
        intents = []
    else:
        if not intents:
            warnings.append("allowed_intents is empty: the bundle admits nothing (lockdown)")
        dupes = sorted({i for i in intents if intents.count(i) > 1})
        if dupes:
            warnings.append(f"duplicate intents ignored: {dupes}")
            seen: list[str] = []
            intents = [i for i in intents if not (i in seen or seen.append(i))]
        unknown = [i for i in intents if i not in INTENT_REGISTRY]
        if unknown:
            errors.append(
                f"unknown intents (not in the executor vocabulary): {sorted(set(unknown))}")

    limits = doc.get("limits") or {}
    if not isinstance(limits, dict) or not all(
        isinstance(v, int | float) and not isinstance(v, bool) for v in limits.values()
    ):
        errors.append("limits must be a mapping of name -> number")
        limits = {}

    if errors:
        return {"valid": False, "errors": errors, "warnings": warnings, "digest": None}

    bundle = PolicyBundle.create(
        version=version,
        allowed_intents=intents,
        limits={k: float(v) for k, v in limits.items()},
        provenance="api:/api/policies/validate",
    )
    return {
        "valid": True,
        "errors": [],
        "warnings": warnings,
        "digest": bundle.digest(),
        "bundle": bundle.as_dict(),
    }
