"""MAESTRO SDK — Typed client library for the MAESTRO Control Plane.

Installation:
    pip install maestro-sdk

Quickstart:
    from maestro.sdk import MaestroClient, AlertIn, AgentType

    client = MaestroClient(
        base_url="https://api.maestro.example.com",
        api_key="your-api-key"
    )

    # Create a coding agent
    agent = client.agents.create(type=AgentType.CODING, tenant="my-tenant")
    print(f"Created agent: {agent.agent_id}")

    # Submit an alert
    alert = AlertIn(cls="dos", severity=0.9, detail="High traffic from 10.0.0.1")
    result = client.alerts.submit(alert)
    print(f"Alert processed: {result.alert_id}")

    # Inspect memory
    records = client.memory.inspect(tenant="my-tenant", tier="episodic")
    print(f"Found {len(records.records)} memory records")

    # Check ledger integrity
    verification = client.ledger.verify()
    print(f"Ledger intact: {verification.intact}")

    client.close()

Async usage:
    async with MaestroClient(base_url="...", api_key="...") as client:
        agent = await client.agents.acreate(type=AgentType.RESEARCH, tenant="my-tenant")
        records = await client.memory.ainspect(tenant="my-tenant")
        verification = await client.ledger.averify()

Documentation: https://maestro.example.com/docs/sdk
"""
from __future__ import annotations

# Main client
# Sub-clients
from maestro.sdk.client import (
    AgentClient,
    AlertClient,
    ControlPlaneClient,
    CritiqueClient,
    LedgerClient,
    MaestroClient,
    MemoryClient,
    PerimeterClient,
    PolicyClient,
    TenantClient,
)

# Exceptions
from maestro.sdk.exceptions import (
    ConfigurationError,
    Conflict,
    MaestroError,
    NotFound,
    RateLimited,
    ServerError,
    TimeoutError,
    Unauthorized,
    ValidationError,
)

# HTTP client (for advanced usage)
from maestro.sdk.http_client import ControlPlaneClient as HttpControlPlaneClient

# Models
from maestro.sdk.models import (
    AgentCreateRequest,
    AgentInfo,
    AgentListResponse,
    AgentStatus,
    AgentType,
    AlertClass,
    AlertIn,
    AlertOut,
    AlertSeverity,
    BlastRadiusResponse,
    ControlPlaneState,
    CritiqueIn,
    CritiqueOut,
    ErrorResponse,
    HaltResponse,
    LedgerEvent,
    LedgerExportResponse,
    LedgerVerifyResponse,
    MemoryInspectRequest,
    MemoryInspectResponse,
    MemoryPromoteRequest,
    MemoryQuarantineRequest,
    MemoryRecord,
    MemoryTier,
    MetricsResponse,
    PerimeterIn,
    PerimeterResult,
    PolicyValidateRequest,
    PolicyValidateResponse,
    SignalOut,
    TenantCreateRequest,
    TenantInfo,
    TrustLabel,
    VariableOut,
)

__version__ = "0.9.0"

__all__ = [
    # Main client
    "MaestroClient",
    
    # Sub-clients
    "AgentClient",
    "PolicyClient",
    "MemoryClient",
    "LedgerClient",
    "TenantClient",
    "PerimeterClient",
    "CritiqueClient",
    "ControlPlaneClient",
    "AlertClient",
    
    # Models - Alerts
    "AlertClass",
    "AlertSeverity",
    "AlertIn",
    "AlertOut",
    
    # Models - Agents
    "AgentType",
    "AgentStatus",
    "AgentCreateRequest",
    "AgentInfo",
    "AgentListResponse",
    
    # Models - Blast Radius
    "BlastRadiusResponse",
    
    # Models - Control Plane
    "ControlPlaneState",
    
    # Models - Critique
    "CritiqueIn",
    "CritiqueOut",
    "HaltResponse",
    
    # Models - Ledger
    "LedgerEvent",
    "LedgerVerifyResponse",
    "LedgerExportResponse",
    
    # Models - Memory
    "MemoryTier",
    "TrustLabel",
    "MemoryRecord",
    "MemoryInspectRequest",
    "MemoryInspectResponse",
    "MemoryPromoteRequest",
    "MemoryQuarantineRequest",
    
    # Models - Metrics
    "MetricsResponse",
    
    # Models - Perimeter
    "PerimeterIn",
    "PerimeterResult",
    "VariableOut",
    "SignalOut",
    
    # Models - Tenants
    "TenantCreateRequest",
    "TenantInfo",
    
    # Models - Policies
    "PolicyValidateRequest",
    "PolicyValidateResponse",
    
    # Models - Errors
    "ErrorResponse",
    
    # Exceptions
    "MaestroError",
    "NotFound",
    "Unauthorized",
    "ValidationError",
    "Conflict",
    "RateLimited",
    "ServerError",
    "ConfigurationError",
    "TimeoutError",
    
    # HTTP client
    "HttpControlPlaneClient",
]