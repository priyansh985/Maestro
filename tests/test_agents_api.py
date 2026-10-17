"""Fleet-management + control-plane extension tests (BP11 surface).

These assert the /api/agents fleet drives *real* platforms: creating an agent
provisions a full AgentPlatform, an alert runs the live control loop, halt trips
that platform's kill switch, and tenant isolation is structural (another
tenant's principal gets a clean 404, leaking nothing). The control-plane
extensions (memory promote/quarantine, tenants, policies, ledger verify/export)
are exercised through the same authenticated client.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from maestro.server.agents_api import REGISTRY
from maestro.server.app import create_app
from maestro.server.auth import AuthService, Role, configure_auth
from maestro.server.control_api import _ISOLATED, _PLANES, _TENANT_META

_SVC = AuthService(key=b"test-fleet-api-key")


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    configure_auth(enforce=True, service=_SVC, control_plane_tenant="default")
    token = _SVC.issue("svc:admin", tenant="default", role=Role.ADMIN, ttl_seconds=3600)
    REGISTRY.clear()
    _PLANES.clear()
    _TENANT_META.clear()
    _ISOLATED.clear()
    c = TestClient(app, headers={"Authorization": f"Bearer {token}"})
    c.post("/api/reset", json={"shadow": False})
    yield c
    REGISTRY.clear()
    _PLANES.clear()
    _TENANT_META.clear()
    _ISOLATED.clear()


def _token(role: Role, tenant: str = "default") -> str:
    return _SVC.issue(f"svc:{role.name.lower()}", tenant=tenant, role=role, ttl_seconds=3600)


# --- fleet lifecycle -------------------------------------------------------- #
def test_create_list_get_delete_roundtrip(client: TestClient) -> None:
    r = client.post("/api/agents", json={"type": "generic", "agent_id": "agent:test:1"})
    assert r.status_code == 201
    info = r.json()
    assert info["agent_id"] == "agent:test:1"
    assert info["status"] == "idle"
    assert info["capabilities"]          # a generic default agent holds capabilities

    listed = client.get("/api/agents").json()
    assert listed["total"] == 1 and listed["agents"][0]["agent_id"] == "agent:test:1"

    detail = client.get("/api/agents/agent:test:1").json()
    assert detail["blast_radius"]["agent_id"] == "agent:test:1"
    assert isinstance(detail["blast_radius"]["holds_irreversible_capability"], bool)
    assert detail["policy_digest"]        # the signed policy bundle is live

    assert client.delete("/api/agents/agent:test:1").json()["deleted"] is True
    assert client.get("/api/agents").json()["total"] == 0


def test_create_each_vertical_type(client: TestClient) -> None:
    for type_, frag in (("coding", "code_"), ("research", "research_"), ("soc", "throttle_telemetry")):
        r = client.post("/api/agents", json={"type": type_})
        assert r.status_code == 201, r.text
        info = r.json()
        assert info["type"] == type_
        assert frag in info["intent_vocabulary"] or any(
            v.startswith(frag) for v in info["intent_vocabulary"])


def test_duplicate_agent_id_conflicts(client: TestClient) -> None:
    client.post("/api/agents", json={"agent_id": "agent:dup:1"})
    r = client.post("/api/agents", json={"agent_id": "agent:dup:1"})
    assert r.status_code == 409


def test_unknown_agent_is_404(client: TestClient) -> None:
    for method, path in (
        ("GET", "/api/agents/agent:ghost:9"),
        ("DELETE", "/api/agents/agent:ghost:9"),
        ("GET", "/api/agents/agent:ghost:9/logs"),
        ("POST", "/api/agents/agent:ghost:9/halt"),
    ):
        r = client.request(method, path)
        assert r.status_code == 404, (method, path, r.status_code)


def test_bad_type_and_bad_intents_rejected(client: TestClient) -> None:
    assert client.post("/api/agents", json={"type": "skynet"}).status_code == 400
    r = client.post("/api/agents", json={"type": "generic", "allowed_intents": ["destroy_all_humans"]})
    assert r.status_code == 400


def test_allowed_intents_can_only_narrow(client: TestClient) -> None:
    r = client.post("/api/agents", json={
        "type": "coding", "allowed_intents": ["code_read", "code_test"]})
    assert r.status_code == 201
    assert sorted(r.json()["intent_vocabulary"]) == ["code_read", "code_test"]


# --- RBAC -------------------------------------------------------------------- #
def test_viewer_cannot_create_but_can_read(client: TestClient) -> None:
    client.post("/api/agents", json={"agent_id": "agent:rbac:1"})
    viewer = {"Authorization": f"Bearer {_token(Role.VIEWER)}"}
    assert client.post("/api/agents", json={"agent_id": "x"},
                       headers=viewer).status_code == 403
    assert client.get("/api/agents", headers=viewer).status_code == 200
    assert client.get("/api/agents/agent:rbac:1", headers=viewer).status_code == 200
    assert client.post("/api/agents/agent:rbac:1/halt",
                       headers=viewer).status_code == 403


# --- structural tenant isolation --------------------------------------------- #
def test_tenant_isolation_is_structural(client: TestClient) -> None:
    client.post("/api/agents", json={"agent_id": "agent:iso:1"})
    other = {"Authorization": f"Bearer {_token(Role.ADMIN, tenant='tenant-b')}"}

    listed = client.get("/api/agents", headers=other).json()
    assert all(a["tenant"] == "tenant-b" for a in listed["agents"]) and listed["total"] == 0

    assert client.get("/api/agents/agent:iso:1", headers=other).status_code == 404
    assert client.delete("/api/agents/agent:iso:1", headers=other).status_code == 404
    # the agent still exists for its own tenant
    assert client.get("/api/agents/agent:iso:1").status_code == 200


# --- driving an agent --------------------------------------------------------- #
def test_alert_runs_live_loop_and_populates_logs(client: TestClient) -> None:
    client.post("/api/agents", json={"type": "soc", "agent_id": "agent:drive:1"})
    r = client.post("/api/agents/agent:drive:1/alert",
                    json={"cls": "dos", "severity": 0.95}).json()
    assert r["agent_id"] == "agent:drive:1"
    assert r["allowed"] is True
    assert r["decision_card"]
    assert "chain_of_thought" not in r["decision_card"]   # CoT-free by construction

    info = client.get("/api/agents/agent:drive:1").json()
    assert info["status"] == "running"
    assert info["ledger_events"] >= 1

    logs = client.get("/api/agents/agent:drive:1/logs").json()
    assert logs["count"] >= 1
    assert "event_hash" in logs["logs"][0]


def test_halt_resume_kill_switch(client: TestClient) -> None:
    # Idempotency keys are (alert class, whole-second ts, intent); sleeping
    # >1s between probes keeps them distinct so each is a genuinely new alert.
    client.post("/api/agents", json={"agent_id": "agent:ks:1"})
    client.post("/api/agents/agent:ks:1/alert", json={"cls": "dos", "detail": "pre-halt probe"})
    time.sleep(1.1)

    assert client.post("/api/agents/agent:ks:1/halt").json()["halted"] is True
    assert client.get("/api/agents/agent:ks:1").json()["status"] == "halted"
    denied = client.post("/api/agents/agent:ks:1/alert",
                         json={"cls": "dos", "detail": "halted probe"}).json()
    assert denied["allowed"] is False                # fail-closed under the kill switch

    client.post("/api/agents/agent:ks:1/resume")
    time.sleep(1.1)
    resumed = client.post("/api/agents/agent:ks:1/alert",
                          json={"cls": "dos", "detail": "post-resume probe"}).json()
    assert resumed["allowed"] is True                # distinct alert key → executes again


def test_shadow_agent_withholds_side_effects(client: TestClient) -> None:
    r = client.post("/api/agents", json={"agent_id": "agent:shadow:1", "shadow": True})
    assert r.json()["shadow_mode"] is True
    out = client.post("/api/agents/agent:shadow:1/alert", json={"cls": "dos"}).json()
    assert out["shadowed"] is True
    assert out["allowed"] is True                    # authorized, but the effect was withheld


def test_logs_limit_param(client: TestClient) -> None:
    client.post("/api/agents", json={"agent_id": "agent:logs:1"})
    for _ in range(3):
        client.post("/api/agents/agent:logs:1/alert", json={"cls": "dos"})
    assert client.get("/api/agents/agent:logs:1/logs", params={"limit": 2}).json()["count"] == 2


# --- control-plane extensions -------------------------------------------------- #
def test_ledger_verify_and_export(client: TestClient) -> None:
    client.post("/api/alert", json={"cls": "dos"})
    v = client.get("/api/ledger/verify").json()
    assert v["intact"] is True and v["events"] >= 1 and v["first_broken_index"] is None
    e = client.get("/api/ledger/export", params={"limit": 5}).json()
    assert e["count"] >= 1 and set(e["events"][0]) >= {"event_id", "event_hash", "hmac"}


def test_memory_promote_and_quarantine_roundtrip(client: TestClient) -> None:
    client.post("/api/alert", json={"cls": "dos"})
    recs = client.get("/api/memory").json()["records"]
    target = next(r for r in recs if r["trust"] == "untrusted")

    p = client.post("/api/memory/promote", json={"record_id": target["record_id"]}).json()
    assert p["promoted"] is True and p["record"]["trust"] == "trusted"

    q = client.post("/api/memory/quarantine", json={"record_id": target["record_id"]}).json()
    assert q["quarantined"] is True and q["record"]["trust"] == "untrusted"

    # refusal-idempotent: quarantining again is a client error, not a silent pass
    assert client.post("/api/memory/quarantine", json={"record_id": target["record_id"]}).status_code == 400
    assert client.post("/api/memory/promote", json={"record_id": "mem:ghost:1"}).status_code == 404


def test_memory_tier_filter(client: TestClient) -> None:
    client.post("/api/alert", json={"cls": "dos"})
    r = client.get("/api/memory", params={"tier": "episodic"}).json()
    assert all(x["tier"] == "episodic" for x in r["records"])
    assert client.get("/api/memory", params={"tier": "bogus"}).status_code == 400


def test_tenants_admin_surface(client: TestClient) -> None:
    r = client.post("/api/tenants", json={"tenant_id": "acme", "display_name": "Acme"})
    assert r.status_code == 201
    assert r.json()["tenant_id"] == "acme"

    assert client.post("/api/tenants", json={"tenant_id": "acme"}).status_code == 409
    assert client.get("/api/tenants/acme").status_code == 200
    assert client.get("/api/tenants/ghost").status_code == 404

    listed = {t["tenant_id"] for t in client.get("/api/tenants").json()["tenants"]}
    assert {"acme", "default"} <= listed

    # isolate trips the tenant's kill switch and halts its fleet agents
    iso = client.post("/api/tenants/acme/isolate").json()
    assert iso["isolated"] is True
    assert client.get("/api/tenants/acme").json()["isolated"] is True

    # non-admins are fenced out of the whole tenants surface
    op = {"Authorization": f"Bearer {_token(Role.OPERATOR)}"}
    assert client.get("/api/tenants", headers=op).status_code == 403


def test_policies_validate(client: TestClient) -> None:
    good = client.post("/api/policies/validate", json={
        "policy_yaml": "version: 2\nallowed_intents: [code_read, code_test]\nlimits: {max_tool_calls: 50}"}).json()
    assert good["valid"] is True and good["digest"].startswith("sha256:")

    bad = client.post("/api/policies/validate", json={
        "policy_yaml": "allowed_intents: [code_read, bogus_intent]"}).json()
    assert bad["valid"] is False and any("bogus_intent" in e for e in bad["errors"])

    broken = client.post("/api/policies/validate", json={
        "policy_yaml": "version: [unclosed"}).json()
    assert broken["valid"] is False

    assert client.post("/api/policies/validate", json={"policy_yaml": "just a string"}).json()["valid"] is False


def test_enriched_decision_payload(client: TestClient) -> None:
    r = client.post("/api/alert", json={"cls": "dos"}).json()
    assert {"alert_id", "tenant", "created_at"} <= set(r)
    assert client.post("/api/halt").json()["message"]
    assert client.post("/api/resume").json()["message"]
    assert isinstance(client.get("/api/blast-radius").json()["holds_irreversible_capability"], bool)
