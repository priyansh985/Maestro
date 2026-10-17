"""MAESTRO SDK — Typed client library for the MAESTRO Control Plane.

Quickstart:
    from maestro.sdk import MaestroClient, AlertIn, AgentType

    client = MaestroClient(base_url="http://127.0.0.1:8000", api_key="your-token")

    # Create a coding agent in your tenant's fleet
    agent = client.agents.create(agent_type=AgentType.CODING)
    print(f"Created agent: {agent.agent_id}")

    # Run an alert through it (reason -> propose -> authorize -> ledger)
    result = client.agents.submit_alert(agent.agent_id, AlertIn(cls="dos", severity=0.9))
    print(f"Decision: {result.decision}")

    # Inspect memory, verify the tamper-evident ledger
    records = client.memory.inspect(tier="episodic")
    verification = client.ledger.verify()
    print(f"Ledger intact: {verification.intact}")

    client.close()

Async usage:
    async with MaestroClient(base_url="...", api_key="...") as client:
        agent = await client.agents.acreate(type=AgentType.RESEARCH)
        records = await client.memory.ainspect()
        verification = await client.ledger.averify()

From the environment:
    client = MaestroClient.from_env()   # MAESTRO_BASE_URL, MAESTRO_API_TOKEN
"""
from __future__ import annotations

# Main client
# Sub-clients
from maestro.sdk.client import (
    AgentClient,
    AlertClient,
    ControlPlaneStateClient,
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

__version__ = "1.0.0"

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
    "ControlPlaneStateClient",
    "AlertClient",

    # Models - Alerts
    "AlertClass",
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
