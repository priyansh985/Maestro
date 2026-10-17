"""Fleet-management REST API: create, inspect, drive, and stop agents (BP11).

Every route operates the *real* agent platforms from
:mod:`maestro.server.agent_registry` — creating an agent provisions a full
``AgentPlatform`` (ledger, scoped memory, capabilities, sandbox, signed policy
bundle); submitting an alert to it runs the live control loop
(reason → propose → authorize → execute → ledger); halting one trips that
platform's kill switch. There is no mock fleet and no bypass path.

Isolation is structural, exactly like the control-plane routes: the registry is
keyed by the authenticated principal's tenant, so a fleet route can only ever
address the caller's own tenant's agents — another tenant's agent id is simply
"not found" (404), leaking nothing.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..telemetry.detection import Alert, AlertClass
from .agent_registry import (
    AGENT_TYPES,
    CapacityError,
    ConflictError,
    REGISTRY,
    AgentRecord,
)
from .auth import Principal, enforce_rate_limit, require_operator, require_viewer

router = APIRouter(
    prefix="/api",
    tags=["agents"],
    dependencies=[Depends(require_viewer), Depends(enforce_rate_limit)],
)


# --------------------------------------------------------------------------- #
# Request models.
# --------------------------------------------------------------------------- #
class AgentCreateIn(BaseModel):
    type: str = Field("generic", description=f"one of {sorted(AGENT_TYPES)}")
    agent_id: str | None = Field(None, description="unique handle within the tenant")
    allowed_intents: list[str] | None = Field(
        None, description="restrict the vocabulary (least privilege); the type's "
        "vocabulary is the ceiling, this can only narrow it")
    shadow: bool = Field(False, description="provision in shadow mode (side effects withheld)")
    controller: str = Field("human:operator", description="the delegating human principal")


class AgentAlertIn(BaseModel):
    cls: str = Field("dos", description="alert class: normal|dos|port_scan|bruteforce|anomaly")
    severity: float = Field(0.9, ge=0.0, le=1.0)
    detail: str = ""


# --------------------------------------------------------------------------- #
# Resolvers: tenant-scoped by the authenticated principal (structural isolation).
# --------------------------------------------------------------------------- #
def _fleet(principal: Principal) -> str:
    return principal.tenant


def _agent(agent_id: str, principal: Principal = Depends(require_viewer)) -> AgentRecord:
    record = REGISTRY.get(principal.tenant, agent_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"agent {agent_id!r} not found")
    return record


def _parse_class(name: str) -> AlertClass:
    try:
        return AlertClass(name.lower())
    except ValueError:
        return AlertClass.ANOMALY


# --------------------------------------------------------------------------- #
# Fleet lifecycle.
# --------------------------------------------------------------------------- #
@router.get("/agents")
def list_agents(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """The caller's tenant fleet: one info row per provisioned agent."""
    agents = [record.info() for record in REGISTRY.list(principal.tenant)]
    return {"agents": agents, "total": len(agents)}


@router.post("/agents", status_code=201)
def create_agent(
    body: AgentCreateIn, principal: Principal = Depends(require_operator)
) -> dict[str, Any]:
    """Provision a new agent in the caller's tenant (a full platform, not a stub)."""
    try:
        record = REGISTRY.create(
            principal.tenant,
            agent_type=body.type,
            agent_id=body.agent_id,
            allowed_intents=body.allowed_intents,
            shadow=body.shadow,
            controller=body.controller,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CapacityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record.info()


@router.get("/agents/{agent_id}")
def get_agent(record: AgentRecord = Depends(_agent)) -> dict[str, Any]:
    """Agent details: live status, capabilities, blast radius, policy digest."""
    info = record.info()
    info["blast_radius"] = record.blast_radius_dict()
    policy = record.platform.policy
    if policy is not None:
        try:
            info["policy_digest"] = policy.active().bundle.digest()
        except Exception:  # noqa: BLE001 - no genesis bundle: report, don't fail
            info["policy_digest"] = None
    return info


@router.delete("/agents/{agent_id}")
def delete_agent(
    record: AgentRecord = Depends(_agent),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    """Remove an agent from the caller's fleet (its ledger history goes with it)."""
    REGISTRY.delete(principal.tenant, record.agent_id)
    return {"deleted": True, "agent_id": record.agent_id}


@router.get("/agents/{agent_id}/logs")
def agent_logs(
    record: AgentRecord = Depends(_agent), limit: int = 100
) -> dict[str, Any]:
    """The agent's audit trail (its hash-chained ledger), most recent first."""
    logs = record.logs(limit=max(1, min(limit, 1000)))
    return {"logs": logs, "count": len(logs)}


@router.get("/agents/{agent_id}/blast-radius")
def agent_blast_radius(record: AgentRecord = Depends(_agent)) -> dict[str, Any]:
    """This agent's bounded reach — legible on one screen (blueprint §2)."""
    return record.blast_radius_dict()


# --------------------------------------------------------------------------- #
# Driving an individual agent.
# --------------------------------------------------------------------------- #
@router.post("/agents/{agent_id}/alert")
def agent_alert(
    body: AgentAlertIn,
    record: AgentRecord = Depends(_agent),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    """Run one alert through this agent's live loop and return the decision card."""
    cls = _parse_class(body.cls)
    detail = body.detail or f"operator-injected {cls.value} alert via fleet API"
    alert = Alert(ts=time.time(), cls=cls, severity=body.severity, detail=detail)
    try:
        result = REGISTRY.submit_alert(principal.tenant, record.agent_id, alert)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"agent loop failed: {exc}") from exc
    return {
        "agent_id": record.agent_id,
        "alert_id": f"{record.agent_id}:{int(alert.ts * 1000)}",
        "tenant": principal.tenant,
        "created_at": alert.ts,
        "alert_class": result.alert_class,
        "proposed_action": result.proposed_action,
        "allowed": result.allowed,
        "decision": result.decision,
        "reason": result.reason,
        "shadowed": result.shadowed,
        "decision_card": result.decision_card,
    }


@router.post("/agents/{agent_id}/halt")
def agent_halt(
    record: AgentRecord = Depends(_agent),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    """Trip this agent's kill switch — it denies all further actions."""
    record.platform.halt()
    return {"agent_id": record.agent_id, "halted": True,
            "message": f"agent {record.agent_id} halted (kill switch tripped)"}


@router.post("/agents/{agent_id}/resume")
def agent_resume(
    record: AgentRecord = Depends(_agent),
    principal: Principal = Depends(require_operator),
) -> dict[str, Any]:
    record.platform.resume()
    return {"agent_id": record.agent_id, "halted": False,
            "message": f"agent {record.agent_id} resumed"}
