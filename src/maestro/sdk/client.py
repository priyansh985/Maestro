"""High-level SDK client classes for MAESTRO."""
from __future__ import annotations

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
    """Client for agent lifecycle management."""
    
    def create(
        self,
        agent_type: AgentType = AgentType.GENERIC,
        tenant: str = "default",
        agent_id: str | None = None,
        allowed_intents: list[str] | None = None,
        shadow: bool = False,
    ) -> AgentInfo:
        """Create a new agent."""
        request = AgentCreateRequest(
            type=agent_type,
            tenant=tenant,
            agent_id=agent_id,
            allowed_intents=allowed_intents,
            shadow=shadow,
        )
        return self._http.create_agent(request)
    
    async def acreate(
        self,
        agent_type: AgentType = AgentType.GENERIC,
        tenant: str = "default",
        agent_id: str | None = None,
        allowed_intents: list[str] | None = None,
        shadow: bool = False,
    ) -> AgentInfo:
        request = AgentCreateRequest(
            type=agent_type,
            tenant=tenant,
            agent_id=agent_id,
            allowed_intents=allowed_intents,
            shadow=shadow,
        )
        return await self._http.acreate_agent(request)
    
    def list_agents(self, tenant: str | None = None) -> AgentListResponse:
        """List all agents."""
        return self._http.list_agents(tenant)
    
    async def alist_agents(self, tenant: str | None = None) -> AgentListResponse:
        return await self._http.alist_agents(tenant)
    
    def get(self, agent_id: str) -> AgentInfo:
        """Get agent details."""
        return self._http.get_agent(agent_id)
    
    async def aget(self, agent_id: str) -> AgentInfo:
        return await self._http.aget_agent(agent_id)
    
    def delete(self, agent_id: str) -> dict:
        """Delete an agent."""
        return self._http.delete_agent(agent_id)
    
    async def adelete(self, agent_id: str) -> dict:
        return await self._http.adelete_agent(agent_id)
    
    def logs(self, agent_id: str, limit: int = 100) -> list[dict]:
        """Get agent logs."""
        return self._http.get_agent_logs(agent_id, limit)
    
    async def alogs(self, agent_id: str, limit: int = 100) -> list[dict]:
        return await self._http.aget_agent_logs(agent_id, limit)
    
    def blast_radius(self) -> BlastRadiusResponse:
        """Get agent's blast radius."""
        return self._http.get_blast_radius()
    
    async def ablast_radius(self) -> BlastRadiusResponse:
        return await self._http.aget_blast_radius()


class PolicyClient(BaseClient):
    """Client for policy management."""
    
    def validate(self, policy_yaml: str) -> PolicyValidateResponse:
        """Validate a policy bundle."""
        request = PolicyValidateRequest(policy_yaml=policy_yaml)
        return self._http.validate_policy(request)
    
    async def avalidate(self, policy_yaml: str) -> PolicyValidateResponse:
        request = PolicyValidateRequest(policy_yaml=policy_yaml)
        return await self._http.avalidate_policy(request)
    
    def get_controls(self) -> dict:
        """Get control status report."""
        return self._http.get_controls()
    
    async def aget_controls(self) -> dict:
        return await self._http.aget_controls()
    
    def get_layers(self) -> dict:
        """Get layer information."""
        return self._http.get_layers()
    
    async def aget_layers(self) -> dict:
        return await self._http.aget_layers()


class MemoryClient(BaseClient):
    """Client for memory inspection and management."""
    
    def inspect(
        self,
        tenant: str,
        tier: MemoryTier | None = None,
        include_untrusted: bool = False,
        limit: int = 100,
    ) -> MemoryInspectResponse:
        """Inspect memory records."""
        request = MemoryInspectRequest(
            tier=tier,
            include_untrusted=include_untrusted,
            limit=limit,
        )
        return self._http.inspect_memory(request, tenant)
    
    async def ainspect(
        self,
        tenant: str,
        tier: MemoryTier | None = None,
        include_untrusted: bool = False,
        limit: int = 100,
    ) -> MemoryInspectResponse:
        request = MemoryInspectRequest(
            tier=tier,
            include_untrusted=include_untrusted,
            limit=limit,
        )
        return await self._http.ainspect_memory(request, tenant)
    
    def promote(
        self,
        tenant: str,
        record_id: str,
        capability: str,
    ) -> dict:
        """Promote a memory record."""
        request = MemoryPromoteRequest(record_id=record_id, capability=capability)
        return self._http.promote_memory(request, tenant)
    
    async def apromote(
        self,
        tenant: str,
        record_id: str,
        capability: str,
    ) -> dict:
        request = MemoryPromoteRequest(record_id=record_id, capability=capability)
        return await self._http.apromote_memory(request, tenant)
    
    def quarantine(
        self,
        tenant: str,
        record_id: str,
    ) -> dict:
        """Quarantine a memory record."""
        request = MemoryQuarantineRequest(record_id=record_id)
        return self._http.quarantine_memory(request, tenant)
    
    async def aquarantine(
        self,
        tenant: str,
        record_id: str,
    ) -> dict:
        request = MemoryQuarantineRequest(record_id=record_id)
        return await self._http.aquarantine_memory(request, tenant)


class LedgerClient(BaseClient):
    """Client for ledger operations."""
    
    def verify(self) -> LedgerVerifyResponse:
        """Verify ledger integrity."""
        return self._http.verify_ledger()
    
    async def averify(self) -> LedgerVerifyResponse:
        return await self._http.averify_ledger()
    
    def export(self, limit: int | None = None) -> LedgerExportResponse:
        """Export ledger events."""
        return self._http.export_ledger(limit)
    
    async def aexport(self, limit: int | None = None) -> LedgerExportResponse:
        return await self._http.aexport_ledger(limit)
    
    def metrics(self) -> MetricsResponse:
        """Get platform metrics."""
        return self._http.get_metrics()
    
    async def ametrics(self) -> MetricsResponse:
        return await self._http.aget_metrics()


class TenantClient(BaseClient):
    """Client for tenant management."""
    
    def create(
        self,
        tenant_id: str,
        display_name: str | None = None,
        quotas: dict | None = None,
    ) -> TenantInfo:
        """Create a new tenant."""
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
        """List all tenants."""
        return self._http.list_tenants()
    
    async def alist_tenants(self) -> list[TenantInfo]:
        return await self._http.alist_tenants()
    
    def get(self, tenant_id: str) -> TenantInfo:
        """Get tenant details."""
        return self._http.get_tenant(tenant_id)
    
    async def aget(self, tenant_id: str) -> TenantInfo:
        return await self._http.aget_tenant(tenant_id)
    
    def isolate(self, tenant_id: str) -> dict:
        """Enforce tenant isolation."""
        return self._http.isolate_tenant(tenant_id)
    
    async def aisloate(self, tenant_id: str) -> dict:
        return await self._http.aisolate_tenant(tenant_id)


class PerimeterClient(BaseClient):
    """Client for the dual-LLM injection perimeter."""
    
    def scan(
        self,
        content: str,
        source: str = "external",
    ) -> PerimeterResult:
        """Scan content through the perimeter."""
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
        """Run critique evaluation."""
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
    """Client for control plane state and operations."""
    
    def state(self) -> ControlPlaneState:
        """Get control plane state."""
        return self._http.get_state()
    
    async def astate(self) -> ControlPlaneState:
        return await self._http.aget_state()
    
    def halt(self) -> HaltResponse:
        """Halt the agent (kill switch)."""
        return self._http.halt()
    
    async def ahalt(self) -> HaltResponse:
        return await self._http.ahalt()
    
    def resume(self) -> HaltResponse:
        """Resume the agent."""
        return self._http.resume()
    
    async def aresume(self) -> HaltResponse:
        return await self._http.aresume()
    
    def reset(self, shadow: bool = False) -> dict:
        """Reset control plane state."""
        return self._http.reset(shadow)
    
    async def areset(self, shadow: bool = False) -> dict:
        return await self._http.areset(shadow)


class MaestroClient:
    """Main entry point for the MAESTRO SDK.
    
    Usage:
        client = MaestroClient(base_url="https://api.maestro.example.com", api_key="...")
        
        # Create an agent
        agent = client.agents.create(type="coding", tenant="my-tenant")
        
        # Submit an alert
        result = client.alerts.submit(AlertIn(cls="dos", severity=0.9, detail="High traffic"))
        
        # Inspect memory
        records = client.memory.inspect(tenant="my-tenant", tier="episodic")
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


class AlertClient(BaseClient):
    """Client for alert submission."""
    
    def submit(self, alert: AlertIn) -> AlertOut:
        """Submit an alert for processing."""
        return self._http.submit_alert(alert)
    
    async def asubmit(self, alert: AlertIn) -> AlertOut:
        return await self._http.asubmit_alert(alert)