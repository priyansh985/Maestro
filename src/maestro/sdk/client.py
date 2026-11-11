"""High-level SDK client classes for MAESTRO.

The tenant is **structural**: every request carries the caller's bearer token,
and the control plane routes it to that principal's tenant partition — there is
no per-call tenant argument to get wrong. Sync and async variants share one
implementation shape (``name`` / ``aname``).
"""
from __future__ import annotations

import os
from typing import Any

from maestro.sdk.http_client import ControlPlaneClient
from maestro.sdk.models import (
    AgentCreateRequest,
    AgentInfo,
    AgentListResponse,
    AgentType,
    AlertIn,
    AlertOut,
    BlastRadiusResponse,
    ControlPlaneState,
    CritiqueIn,
    CritiqueOut,
    HaltResponse,
    LedgerExportResponse,
    LedgerVerifyResponse,
    MemoryInspectRequest,
    MemoryInspectResponse,
    MemoryPromoteRequest,
    MemoryQuarantineRequest,
    MemoryTier,
    MetricsResponse,
    PerimeterIn,
    PerimeterResult,
    PolicyValidateRequest,
    PolicyValidateResponse,
    TenantCreateRequest,
    TenantInfo,
)


class BaseClient:
    """Base class for SDK clients."""

    def __init__(self, http_client: ControlPlaneClient):
        self._http = http_client

    @property
    def http(self) -> ControlPlaneClient:
        return self._http


class AgentClient(BaseClient):
    """Client for agent fleet lifecycle and control.

    Every agent is a fully provisioned platform — creating one mints its
    capabilities, ledger, scoped memory, sandbox, and signed policy bundle.
    """

    def create(
        self,
        agent_type: AgentType | str = AgentType.GENERIC,
        agent_id: str | None = None,
        allowed_intents: list[str] | None = None,
        shadow: bool = False,
    ) -> AgentInfo:
        """Provision a new agent in the caller's tenant."""
        request = AgentCreateRequest(
            type=agent_type,
            agent_id=agent_id,
            allowed_intents=allowed_intents,
            shadow=shadow,
        )
        return self._http.create_agent(request)

    async def acreate(
        self,
        agent_type: AgentType | str = AgentType.GENERIC,
        agent_id: str | None = None,
        allowed_intents: list[str] | None = None,
        shadow: bool = False,
    ) -> AgentInfo:
        request = AgentCreateRequest(
            type=agent_type,
            agent_id=agent_id,
            allowed_intents=allowed_intents,
            shadow=shadow,
        )
        return await self._http.acreate_agent(request)

    def list_agents(self) -> AgentListResponse:
        """List the caller's tenant fleet."""
        return self._http.list_agents()

    async def alist_agents(self) -> AgentListResponse:
        return await self._http.alist_agents()

    def get(self, agent_id: str) -> AgentInfo:
        """Get agent details (includes blast radius and policy digest)."""
        return self._http.get_agent(agent_id)

    async def aget(self, agent_id: str) -> AgentInfo:
        return await self._http.aget_agent(agent_id)

    def delete(self, agent_id: str) -> dict:
        """Remove an agent from the fleet (its ledger history goes with it)."""
        return self._http.delete_agent(agent_id)

    async def adelete(self, agent_id: str) -> dict:
        return await self._http.adelete_agent(agent_id)

    def logs(self, agent_id: str, limit: int = 100) -> list[dict]:
        """The agent's audit trail (its hash-chained ledger), newest first."""
        return self._http.get_agent_logs(agent_id, limit)

    async def alogs(self, agent_id: str, limit: int = 100) -> list[dict]:
        return await self._http.aget_agent_logs(agent_id, limit)

    def blast_radius(self, agent_id: str) -> BlastRadiusResponse:
        """This agent's bounded reach (capabilities, reversible/irreversible)."""
        return self._http.get_agent_blast_radius(agent_id)

    async def ablast_radius(self, agent_id: str) -> BlastRadiusResponse:
        return await self._http.aget_agent_blast_radius(agent_id)

    def submit_alert(self, agent_id: str, alert: AlertIn) -> AlertOut:
        """Run one alert through this agent's live loop; returns the decision card."""
        return self._http.submit_agent_alert(agent_id, alert)

    async def asubmit_alert(self, agent_id: str, alert: AlertIn) -> AlertOut:
        return await self._http.asubmit_agent_alert(agent_id, alert)

    def halt(self, agent_id: str) -> HaltResponse:
        """Trip this agent's kill switch — it denies all further actions."""
        return self._http.halt_agent(agent_id)

    async def ahalt(self, agent_id: str) -> HaltResponse:
        return await self._http.ahalt_agent(agent_id)

    def resume(self, agent_id: str) -> HaltResponse:
        """Clear this agent's kill switch."""
        return self._http.resume_agent(agent_id)

    async def aresume(self, agent_id: str) -> HaltResponse:
        return await self._http.aresume_agent(agent_id)


class PolicyClient(BaseClient):
    """Client for policy management."""

    def validate(self, policy_yaml: str) -> PolicyValidateResponse:
        """Validate a YAML policy bundle against the executor contract (dry-run)."""
        request = PolicyValidateRequest(policy_yaml=policy_yaml)
        return self._http.validate_policy(request)

    async def avalidate(self, policy_yaml: str) -> PolicyValidateResponse:
        request = PolicyValidateRequest(policy_yaml=policy_yaml)
        return await self._http.avalidate_policy(request)

    def get_controls(self) -> dict:
        """Get the control status truth-audit report."""
        return self._http.get_controls()

    async def aget_controls(self) -> dict:
        return await self._http.aget_controls()

    def get_layers(self) -> dict:
        """Get the 7-layer model and the threat-risk matrix."""
        return self._http.get_layers()

    async def aget_layers(self) -> dict:
        return await self._http.aget_layers()


class MemoryClient(BaseClient):
    """Client for memory inspection and management.

    Operates on the caller's tenant scope (structural isolation): promote moves
    a quarantined record to trusted under operator authority; quarantine demotes
    a trusted record so it stops influencing the agent.
    """

    def inspect(
        self,
        tier: MemoryTier | str | None = None,
        include_untrusted: bool = True,
        limit: int = 100,
    ) -> MemoryInspectResponse:
        """Inspect memory records (the caller's tenant + default plane scope)."""
        request = MemoryInspectRequest(
            tier=tier,
            include_untrusted=include_untrusted,
            limit=limit,
        )
        return self._http.inspect_memory(request)

    async def ainspect(
        self,
        tier: MemoryTier | str | None = None,
        include_untrusted: bool = True,
        limit: int = 100,
    ) -> MemoryInspectResponse:
        request = MemoryInspectRequest(
            tier=tier,
            include_untrusted=include_untrusted,
            limit=limit,
        )
        return await self._http.ainspect_memory(request)

    def promote(self, record_id: str) -> dict:
        """Promote a quarantined record to trusted (operator-gated, ledgered)."""
        request = MemoryPromoteRequest(record_id=record_id)
        return self._http.promote_memory(request)

    async def apromote(self, record_id: str) -> dict:
        request = MemoryPromoteRequest(record_id=record_id)
        return await self._http.apromote_memory(request)

    def quarantine(self, record_id: str) -> dict:
        """Quarantine a trusted record (demote to untrusted)."""
        request = MemoryQuarantineRequest(record_id=record_id)
        return self._http.quarantine_memory(request)

    async def aquarantine(self, record_id: str) -> dict:
        request = MemoryQuarantineRequest(record_id=record_id)
        return await self._http.aquarantine_memory(request)


class LedgerClient(BaseClient):
    """Client for ledger operations."""

    def verify(self) -> LedgerVerifyResponse:
        """Verify the hash chain + HMACs; ``intact`` is the tamper check."""
        return self._http.verify_ledger()

    async def averify(self) -> LedgerVerifyResponse:
        return await self._http.averify_ledger()

    def export(self, limit: int | None = None) -> LedgerExportResponse:
        """Export ledger events (most recent last, as the chain is ordered)."""
        return self._http.export_ledger(limit)

    async def aexport(self, limit: int | None = None) -> LedgerExportResponse:
        return await self._http.aexport_ledger(limit)

    def metrics(self) -> MetricsResponse:
        """Ledger-derived operational metrics."""
        return self._http.get_metrics()

    async def ametrics(self) -> MetricsResponse:
        return await self._http.aget_metrics()


class TenantClient(BaseClient):
    """Client for tenant administration (control-plane ADMIN role required)."""

    def create(
        self,
        tenant_id: str,
        display_name: str | None = None,
        quotas: dict | None = None,
    ) -> TenantInfo:
        """Register a new tenant partition."""
        request = TenantCreateRequest(
            tenant_id=tenant_id,
            display_name=display_name,
            quotas=quotas,
        )
        return self._http.create_tenant(request)

    async def acreate(
        self,
        tenant_id: str,
        display_name: str | None = None,
        quotas: dict | None = None,
    ) -> TenantInfo:
        request = TenantCreateRequest(
            tenant_id=tenant_id,
            display_name=display_name,
            quotas=quotas,
        )
        return await self._http.acreate_tenant(request)

    def list_tenants(self) -> list[TenantInfo]:
        """List every known tenant partition."""
        return self._http.list_tenants()

    async def alist_tenants(self) -> list[TenantInfo]:
        return await self._http.alist_tenants()

    def get(self, tenant_id: str) -> TenantInfo:
        """Get tenant details."""
        return self._http.get_tenant(tenant_id)

    async def aget(self, tenant_id: str) -> TenantInfo:
        return await self._http.aget_tenant(tenant_id)

    def isolate(self, tenant_id: str) -> dict:
        """Containment: halt the tenant's plane and every agent in its fleet."""
        return self._http.isolate_tenant(tenant_id)

    async def aisolate(self, tenant_id: str) -> dict:
        return await self._http.aisolate_tenant(tenant_id)


class PerimeterClient(BaseClient):
    """Client for the dual-LLM injection perimeter."""

    def scan(
        self,
        content: str,
        source: str = "external",
    ) -> PerimeterResult:
        """Rule on untrusted content through the perimeter."""
        request = PerimeterIn(content=content, source=source)
        return self._http.scan_perimeter(request)

    async def ascan(
        self,
        content: str,
        source: str = "external",
    ) -> PerimeterResult:
        request = PerimeterIn(content=content, source=source)
        return await self._http.ascan_perimeter(request)


class CritiqueClient(BaseClient):
    """Client for pre-execution critique gate."""

    def evaluate(
        self,
        text: str,
        grounding: list[str],
    ) -> CritiqueOut:
        """Run critique evaluation (HMDC pipeline)."""
        request = CritiqueIn(text=text, grounding=grounding)
        return self._http.critique(request)

    async def aevaluate(
        self,
        text: str,
        grounding: list[str],
    ) -> CritiqueOut:
        request = CritiqueIn(text=text, grounding=grounding)
        return await self._http.acritique(request)


class ControlPlaneStateClient(BaseClient):
    """Client for the default control-plane state and operations."""

    def state(self) -> ControlPlaneState:
        """One-screen snapshot: mode, kill switch, blast radius, ledger depth."""
        return self._http.get_state()

    async def astate(self) -> ControlPlaneState:
        return await self._http.aget_state()

    def blast_radius(self) -> BlastRadiusResponse:
        """The default plane's blast radius."""
        return self._http.get_blast_radius()

    async def ablast_radius(self) -> BlastRadiusResponse:
        return await self._http.aget_blast_radius()

    def halt(self) -> HaltResponse:
        """Halt the default plane (kill switch)."""
        return self._http.halt()

    async def ahalt(self) -> HaltResponse:
        return await self._http.ahalt()

    def resume(self) -> HaltResponse:
        """Resume the default plane."""
        return self._http.resume()

    async def aresume(self) -> HaltResponse:
        return await self._http.aresume()

    def reset(self, shadow: bool = False) -> dict:
        """Rebuild the caller's tenant plane (clears ledger/memory); ADMIN."""
        return self._http.reset(shadow)

    async def areset(self, shadow: bool = False) -> dict:
        return await self._http.areset(shadow)


class AlertClient(BaseClient):
    """Client for alert submission to the default plane."""

    def submit(self, alert: AlertIn) -> AlertOut:
        """Submit an alert for processing through the live loop."""
        return self._http.submit_alert(alert)

    async def asubmit(self, alert: AlertIn) -> AlertOut:
        return await self._http.asubmit_alert(alert)


class MaestroClient:
    """Main entry point for the MAESTRO SDK.

    Usage:
        client = MaestroClient(base_url="https://api.maestro.example.com", api_key="...")

        # Create and drive a fleet agent
        agent = client.agents.create(type="coding")
        result = client.agents.submit_alert(agent.agent_id, AlertIn(cls="dos", severity=0.9))

        # Inspect memory, verify the ledger
        records = client.memory.inspect(tier="episodic")
        client.ledger.verify()

    Or from the environment::

        client = MaestroClient.from_env()   # MAESTRO_BASE_URL, MAESTRO_API_TOKEN
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_backoff: float = 1.0,
    ):
        self._http = ControlPlaneClient(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
        )

        # Initialize sub-clients
        self.agents = AgentClient(self._http)
        self.policies = PolicyClient(self._http)
        self.memory = MemoryClient(self._http)
        self.ledger = LedgerClient(self._http)
        self.tenants = TenantClient(self._http)
        self.perimeter = PerimeterClient(self._http)
        self.critique = CritiqueClient(self._http)
        self.control_plane = ControlPlaneStateClient(self._http)
        self.alerts = AlertClient(self._http)

    @classmethod
    def from_env(cls, **overrides) -> MaestroClient:
        """Build a client from ``MAESTRO_BASE_URL`` and ``MAESTRO_API_TOKEN``."""
        kwargs: dict[str, Any] = {
            "base_url": os.environ.get("MAESTRO_BASE_URL", "http://127.0.0.1:8000"),
            "api_key": os.environ.get("MAESTRO_API_TOKEN"),
        }
        kwargs.update(overrides)
        return cls(**kwargs)

    def close(self) -> None:
        """Close synchronous connections."""
        self._http.close()

    async def aclose(self) -> None:
        """Close asynchronous connections."""
        await self._http.aclose()

    def __enter__(self) -> MaestroClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    async def __aenter__(self) -> MaestroClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()
