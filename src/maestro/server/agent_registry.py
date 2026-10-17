"""Per-tenant registry of live agent platforms — the fleet surface (BP11).

The dashboard and SDK manage *fleets* of agents: the generic network monitor,
secure-coding, research, and SOC verticals. Each fleet entry is a fully
provisioned :class:`~maestro.platform.AgentPlatform` — its own ledger, scoped
memory, capabilities, sandbox, and policy bundle — created through the same
public constructors the verticals ship with, so every security control that
guards a platform created any other way guards these identically.

Isolation mirrors ``control_api._TenantPlanes`` (CTRL-L4-08): the registry is
keyed by tenant and every accessor takes the caller's tenant, so one tenant's
fleet is structurally unreachable from another — there is no cross-tenant
lookup to get wrong at a call site.

Status is derived from live platform state, never stored ahead of truth:
``halted`` reflects the kill switch, ``error`` the last exception surfaced by
the control loop, ``running`` an agent that has handled at least one alert,
``idle`` one provisioned but not yet exercised.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from ..platform import AgentPlatform
from ..telemetry.detection import Alert

#: Fleet agent types and the vocabulary/reasoner each provisions.
AGENT_TYPES: dict[str, str] = {
    "generic": "agent:generic",
    "coding": "agent:secure-coding",
    "research": "agent:research",
    "soc": "agent:soc-network-monitor",
}

#: Upper bound on fleet size per tenant — an operator-created agent consumes
#: process memory (ledger + memory store), so creation is bounded, not unbounded.
MAX_AGENTS_PER_TENANT = 100

_VALID_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._-")


def _default_agent_id(agent_type: str) -> str:
    return f"agent:{agent_type}:{secrets.token_hex(4)}"


def _build_platform(
    agent_type: str,
    *,
    tenant: str,
    agent_id: str,
    controller: str,
    allowed_intents: list[str] | None,
    shadow: bool,
) -> AgentPlatform:
    """Provision one platform of the requested type from public constructors."""
    if agent_type == "generic":
        return AgentPlatform(
            tenant=tenant,
            controller=controller,
            agent_id=agent_id,
            allowed_intents=allowed_intents,
            shadow=shadow,
        )
    if agent_type == "coding":
        from ..agents.coding import CodingReasoner

        vocabulary = list(CodingReasoner.CODING_VOCABULARY)
        if allowed_intents is not None:
            vocabulary = [i for i in vocabulary if i in set(allowed_intents)]
        return AgentPlatform(
            reasoner=CodingReasoner(repo_root="."),
            tenant=tenant,
            controller=controller,
            agent_id=agent_id,
            allowed_intents=vocabulary,
            shadow=shadow,
        )
    if agent_type == "research":
        from ..agents.research import ResearchReasoner

        vocabulary = list(ResearchReasoner.RESEARCH_VOCABULARY)
        if allowed_intents is not None:
            vocabulary = [i for i in vocabulary if i in set(allowed_intents)]
        return AgentPlatform(
            reasoner=ResearchReasoner(),
            tenant=tenant,
            controller=controller,
            agent_id=agent_id,
            allowed_intents=vocabulary,
            shadow=shadow,
        )
    if agent_type == "soc":
        from ..domains.soc_vertical import SOCReasoner

        vocabulary = [
            "noop", "throttle_telemetry", "raise_thresholds",
            "raise_capture_duration", "alert_operator", "promote_memory",
        ]
        if allowed_intents is not None:
            vocabulary = [i for i in vocabulary if i in set(allowed_intents)]
        return AgentPlatform(
            reasoner=SOCReasoner(),
            tenant=tenant,
            controller=controller,
            agent_id=agent_id,
            allowed_intents=vocabulary,
            shadow=shadow,
        )
    raise ValueError(
        f"unknown agent type {agent_type!r}; expected one of {sorted(AGENT_TYPES)}")


@dataclass
class AgentRecord:
    """One fleet entry: a provisioned platform plus its bookkeeping."""

    agent_id: str
    type: str
    platform: AgentPlatform
    created_at: float = field(default_factory=time.time)
    last_active: float | None = None
    error: str | None = None

    def status(self) -> str:
        """Live status derived from the platform, never cached ahead of truth."""
        if self.error is not None:
            return "error"
        if self.platform.pep.halted:
            return "halted"
        if self.last_active is not None:
            return "running"
        return "idle"

    def memory_tiers(self) -> dict[str, int]:
        store, scope = self.platform.memory, self.platform.scope
        records = store.recall(scope, include_untrusted=True)
        tiers = {"working": 0, "episodic": 0, "semantic": 0, "procedural": 0}
        for record in records:
            tiers[record.tier.value] = tiers.get(record.tier.value, 0) + 1
        return tiers

    def info(self) -> dict[str, Any]:
        blast = self.platform.blast_radius()
        return {
            "agent_id": self.agent_id,
            "tenant": self.platform.scope.tenant,
            "type": self.type,
            "status": self.status(),
            "shadow_mode": self.platform.shadow,
            "capabilities": list(blast.capabilities),
            "intent_vocabulary": list(blast.intent_vocabulary),
            "ledger_events": len(self.platform.ledger),
            "memory_tiers": self.memory_tiers(),
            "created_at": self.created_at,
            "last_active": self.last_active,
            "error": self.error,
        }

    def logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """This agent's ledger events, most recent first (the audit trail *is*
        the log — there is no separate, spoofable log stream)."""
        from dataclasses import asdict

        events = list(self.platform.ledger.events)
        return [asdict(e) for e in events[-limit:][::-1]]

    def blast_radius_dict(self) -> dict[str, Any]:
        blast = self.platform.blast_radius()
        d = blast.as_dict()
        d["holds_irreversible_capability"] = blast.holds_irreversible_capability
        d["summary"] = blast.summary()
        return d


class TenantAgentRegistry:
    """Fleet registry partitioned by tenant (structural isolation, CTRL-L4-08)."""

    def __init__(self) -> None:
        self._fleets: dict[str, dict[str, AgentRecord]] = {}

    def create(
        self,
        tenant: str,
        *,
        agent_type: str = "generic",
        agent_id: str | None = None,
        allowed_intents: list[str] | None = None,
        shadow: bool = False,
        controller: str = "human:operator",
    ) -> AgentRecord:
        fleet = self._fleets.setdefault(tenant, {})
        if len(fleet) >= MAX_AGENTS_PER_TENANT:
            raise CapacityError(
                f"tenant {tenant!r} fleet is at the cap of {MAX_AGENTS_PER_TENANT} agents")
        resolved = agent_id or _default_agent_id(agent_type)
        if not resolved or not set(resolved) <= _VALID_ID_CHARS:
            raise ValueError(
                "agent_id must be non-empty and limited to [A-Za-z0-9:._-]")
        if resolved in fleet:
            raise ConflictError(f"agent {resolved!r} already exists in tenant {tenant!r}")
        if agent_type not in AGENT_TYPES:
            raise ValueError(
                f"unknown agent type {agent_type!r}; expected one of {sorted(AGENT_TYPES)}")
        platform = _build_platform(
            agent_type, tenant=tenant, agent_id=resolved, controller=controller,
            allowed_intents=allowed_intents, shadow=shadow)
        record = AgentRecord(
            agent_id=resolved, type=agent_type, platform=platform)
        fleet[resolved] = record
        return record

    def list(self, tenant: str) -> list[AgentRecord]:
        return sorted(self._fleets.get(tenant, {}).values(), key=lambda r: r.created_at)

    def get(self, tenant: str, agent_id: str) -> AgentRecord | None:
        return self._fleets.get(tenant, {}).get(agent_id)

    def delete(self, tenant: str, agent_id: str) -> bool:
        return self._fleets.get(tenant, {}).pop(agent_id, None) is not None

    def halt_all(self, tenant: str) -> int:
        """Trip the kill switch on every agent in a tenant (containment)."""
        count = 0
        for record in self._fleets.get(tenant, {}).values():
            record.platform.halt()
            count += 1
        return count

    def submit_alert(self, tenant: str, agent_id: str, alert: Alert):
        """Run one alert through the named agent; record activity or error."""
        record = self.get(tenant, agent_id)
        if record is None:
            raise KeyError(agent_id)
        try:
            result = record.platform.handle_alert(alert)
        except Exception as exc:  # the loop surfaced a fault — park it on the record
            record.error = f"{type(exc).__name__}: {exc}"
            record.last_active = time.time()
            raise
        record.error = None
        record.last_active = time.time()
        return result

    def tenants(self) -> list[str]:
        """Tenant ids that have a fleet (union with the planes registry is the
        control plane's view of known tenants)."""
        return sorted(t for t, fleet in self._fleets.items() if fleet)

    def clear(self) -> None:
        """Drop all fleets (tests)."""
        self._fleets.clear()


class CapacityError(Exception):
    """Fleet cap reached; creation refused rather than unbounded."""


class ConflictError(Exception):
    """An agent with the same id already exists in the tenant."""


#: Process-scoped singleton, routed to exclusively via the caller's tenant.
REGISTRY = TenantAgentRegistry()
