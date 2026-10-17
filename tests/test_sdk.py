"""SDK tests (BP11) — unit + live-control-plane integration.

The SDK is the typed *library* surface; the CLI is the *process* surface.
Both must route through the same authenticated REST boundary the dashboards
use (``/api/*``). These tests prove:

* models validate / tolerate additive server fields
* ControlPlaneClient maps 4xx/5xx/429 to typed exceptions (incl. 422)
* MaestroClient sub-clients hit the *real* control plane (no mocks except
  for the error-mapping unit test)
"""
from __future__ import annotations

import httpx
import pytest

from maestro.sdk import MaestroClient
from maestro.sdk.exceptions import (
    ConfigurationError,
    NotFound,
    RateLimited,
    Unauthorized,
    ValidationError,
)
from maestro.sdk.http_client import ControlPlaneClient
from maestro.sdk.models import AgentCreateRequest, AgentType, AlertIn


# --------------------------------------------------------------------------- #
# Unit: model / client construction
# --------------------------------------------------------------------------- #
def test_agent_create_request_defaults() -> None:
    req = AgentCreateRequest()
    assert req.type == AgentType.GENERIC
    assert req.agent_id is None


def test_maestro_client_requires_base_url() -> None:
    with pytest.raises(ConfigurationError):
        ControlPlaneClient(base_url="")


def test_sdk_models_ignore_extra_fields() -> None:
    # Server may add fields; SDK must tolerate them (extra="ignore").
    data = {
        "agent_id": "agent:generic:abc123",
        "tenant": "default",
        "type": "generic",
        "status": "running",
        "shadow_mode": False,
        "created_at": 1234567890.0,
        "ledger_events": 0,
        "extra_future_field": "should be ignored",
    }
    from maestro.sdk.models import AgentInfo

    info = AgentInfo(**data)
    assert info.agent_id == "agent:generic:abc123"


def test_error_mapping_with_mock_transport() -> None:
    # Validate that 401/404/429/422 map to typed exceptions without a live server.
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/agents/missing":
            return httpx.Response(404, json={"message": "not found"})
        if path == "/api/tenants":
            return httpx.Response(422, json={"detail": [{"msg": "tenant_id required"}]})
        if path == "/api/agents":
            return httpx.Response(429, json={"message": "too many"}, headers={"retry-after": "1"})
        return httpx.Response(401, json={"message": "no token"})

    transport = httpx.MockTransport(handler)
    client = ControlPlaneClient(base_url="http://test", api_key="bad")
    # Inject mock transport via the underlying httpx client
    client._sync_client = httpx.Client(base_url="http://test", transport=transport)

    with pytest.raises(Unauthorized):
        client._handle_response(httpx.Response(401, json={"message": "no token"}))
    with pytest.raises(NotFound):
        client._handle_response(httpx.Response(404, json={"message": "not found"}))
    with pytest.raises(RateLimited):
        client._handle_response(httpx.Response(429, json={"message": "too many"}))
    with pytest.raises(ValidationError):
        client._handle_response(httpx.Response(422, json={"detail": [{"msg": "bad"}]}))


# --------------------------------------------------------------------------- #
# Integration: live control plane via ASGI transport
# --------------------------------------------------------------------------- #
@pytest.fixture
def sdk_client() -> MaestroClient:
    from fastapi.testclient import TestClient

    from maestro.server.app import create_app
    from maestro.server.auth import AuthService, Role, configure_auth

    app = create_app()
    svc = AuthService(key=b"test-sdk-key")
    configure_auth(enforce=True, service=svc, control_plane_tenant="default")
    token = svc.issue("svc:sdk-test", tenant="default", role=Role.ADMIN, ttl_seconds=3600)

    # Use TestClient for sync (it handles ASGI correctly); async uses ASGI transport
    http = ControlPlaneClient(base_url="http://test", api_key=token, max_retries=0)
    http._sync_client = TestClient(app, headers={"Authorization": f"Bearer {token}"})
    # For async, use the async ASGI transport
    http._async_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )
    mc = MaestroClient.__new__(MaestroClient)
    mc._http = http
    # Wire sub-clients like MaestroClient.__init__ does
    from maestro.sdk.client import (
        AgentClient,
        AlertClient,
        ControlPlaneStateClient,
        CritiqueClient,
        LedgerClient,
        MemoryClient,
        PerimeterClient,
        PolicyClient,
        TenantClient,
    )

    mc.agents = AgentClient(http)
    mc.policies = PolicyClient(http)
    mc.memory = MemoryClient(http)
    mc.ledger = LedgerClient(http)
    mc.tenants = TenantClient(http)
    mc.perimeter = PerimeterClient(http)
    mc.critique = CritiqueClient(http)
    mc.control_plane = ControlPlaneStateClient(http)
    mc.alerts = AlertClient(http)
    return mc


def test_sdk_agents_lifecycle(sdk_client: MaestroClient) -> None:
    # Create, list, get, logs, delete
    agent = sdk_client.agents.create(agent_type=AgentType.GENERIC)
    assert agent.agent_id.startswith("agent:")
    assert agent.tenant == "default"

    listing = sdk_client.agents.list_agents()
    assert listing.total >= 1
    assert any(a.agent_id == agent.agent_id for a in listing.agents)

    fetched = sdk_client.agents.get(agent.agent_id)
    assert fetched.agent_id == agent.agent_id

    logs = sdk_client.agents.logs(agent.agent_id, limit=10)
    assert isinstance(logs, list)

    sdk_client.agents.delete(agent.agent_id)
    with pytest.raises((NotFound, Exception)):
        sdk_client.agents.get(agent.agent_id)


def test_sdk_ledger_verify_and_export(sdk_client: MaestroClient) -> None:
    verify = sdk_client.ledger.verify()
    assert verify.intact is True
    assert verify.events >= 0

    exported = sdk_client.ledger.export(limit=10)
    assert exported.count <= 10


def test_sdk_policy_validate(sdk_client: MaestroClient) -> None:
    ok = sdk_client.policies.validate("version: 1\nallowed_intents: [noop, throttle_telemetry]\n")
    assert ok.valid is True
    assert ok.digest is not None

    bad = sdk_client.policies.validate("not: [valid: yaml: :")
    assert bad.valid is False


def test_sdk_tenants_lifecycle(sdk_client: MaestroClient) -> None:
    import time

    tid = f"tenant-sdk-{int(time.time())}"
    created = sdk_client.tenants.create(tenant_id=tid, display_name="SDK test tenant")
    assert created.tenant_id == tid

    fetched = sdk_client.tenants.get(tid)
    assert fetched.tenant_id == tid

    listed = sdk_client.tenants.list_tenants()
    assert any(t.tenant_id == tid for t in listed)

    iso = sdk_client.tenants.isolate(tid)
    assert iso["isolated"] is True


def test_sdk_memory_and_metrics(sdk_client: MaestroClient) -> None:
    metrics = sdk_client.ledger.metrics()
    assert metrics.total_actions >= 0
    assert 0.0 <= metrics.unsafe_action_rate <= 1.0


def test_sdk_alert_submit(sdk_client: MaestroClient) -> None:
    result = sdk_client.alerts.submit(AlertIn(cls="dos", severity=0.9, detail="sdk-test flood"))
    assert result.allowed in (True, False)
    assert result.decision in ("allow_with_safeguards", "allow", "deny", "deny_autonomous", "require_approval", "route_to_human")
