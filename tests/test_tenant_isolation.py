"""Adversarial tests for structural multi-tenant isolation (CTRL-L4-08, BP3.3).

The control plane is partitioned by tenant: each authenticated principal is
routed to its own live ``AgentPlatform`` + ledger + memory, and no route can
reach another tenant's. These are the *bypass* tests that let CTRL-L4-08 be
graded ``verified``: one tenant must never observe or mutate another's state via
any endpoint, and a tenant claim cannot be spoofed without the signing key.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from maestro.server.app import create_app
from maestro.server.auth import AuthService, Role, configure_auth
from maestro.server.control_api import _PLANES


@dataclass
class Harness:
    app: object
    svc: AuthService

    def client(self, *, tenant: str, role: Role = Role.ADMIN) -> TestClient:
        tok = self.svc.issue("svc:test", tenant=tenant, role=role)
        return TestClient(self.app, headers={"Authorization": f"Bearer {tok}"})


@pytest.fixture
def h() -> Harness:
    app = create_app()
    svc = AuthService(key=b"tenant-iso-key")
    configure_auth(enforce=True, service=svc, control_plane_tenant="default")
    _PLANES.clear()  # start with no tenant planes
    return Harness(app, svc)


def _submit_alert(client: TestClient) -> None:
    assert client.post("/api/alert", json={"cls": "dos"}).status_code == 200


# --- a tenant's writes are invisible to another tenant --------------------- #
def test_ledger_is_isolated_between_tenants(h: Harness) -> None:
    _submit_alert(h.client(tenant="acme"))          # writes to acme's ledger
    assert h.client(tenant="acme").get("/api/ledger").json()["count"] >= 1
    # globex sees a fresh, empty ledger — never acme's events.
    assert h.client(tenant="globex").get("/api/ledger").json()["count"] == 0


def test_state_and_memory_are_isolated_between_tenants(h: Harness) -> None:
    _submit_alert(h.client(tenant="acme"))
    acme_state = h.client(tenant="acme").get("/api/state").json()
    globex_state = h.client(tenant="globex").get("/api/state").json()
    assert acme_state["tenant"] == "acme" and acme_state["ledger_events"] >= 1
    assert globex_state["tenant"] == "globex" and globex_state["ledger_events"] == 0
    # Episodic memory is scoped too: acme quarantines a record, globex sees none.
    assert h.client(tenant="acme").get("/api/memory").json()["count"] >= 1
    assert h.client(tenant="globex").get("/api/memory").json()["count"] == 0


# --- a tenant cannot mutate another tenant's plane ------------------------- #
def test_reset_only_clears_the_callers_own_tenant(h: Harness) -> None:
    _submit_alert(h.client(tenant="acme"))
    # An admin of globex resets — it must NOT touch acme's plane.
    assert h.client(tenant="globex").post("/api/reset", json={"shadow": False}).status_code == 200
    assert h.client(tenant="acme").get("/api/ledger").json()["count"] >= 1
    # acme's own admin reset clears acme.
    h.client(tenant="acme").post("/api/reset", json={"shadow": False})
    assert h.client(tenant="acme").get("/api/ledger").json()["count"] == 0


def test_halt_is_isolated_between_tenants(h: Harness) -> None:
    assert h.client(tenant="acme").post("/api/halt").status_code == 200
    assert h.client(tenant="acme").get("/api/state").json()["halted"] is True
    # globex's kill switch is untouched — its plane still runs.
    assert h.client(tenant="globex").get("/api/state").json()["halted"] is False


def test_reset_response_names_only_the_callers_tenant(h: Harness) -> None:
    body = h.client(tenant="acme").post("/api/reset", json={"shadow": False}).json()
    assert body["tenant"] == "acme"


# --- the tenant claim cannot be forged ------------------------------------- #
def test_tenant_claim_cannot_be_spoofed_without_the_signing_key(h: Harness) -> None:
    # A token minted for "acme" with the WRONG key must be rejected outright —
    # you cannot fabricate a tenant partition you were not issued into.
    forged = AuthService(key=b"attacker-key").issue(
        "svc:evil", tenant="acme", role=Role.ADMIN)
    intruder = TestClient(h.app, headers={"Authorization": f"Bearer {forged}"})
    assert intruder.get("/api/ledger").status_code == 401


# --- the connectors bench is deliberately shared infrastructure ------------ #
def test_connectors_bench_is_shared_across_tenants(h: Harness) -> None:
    # The model-testing/connectors API is shared infra (provider config, not
    # per-tenant customer data), so any authenticated tenant may reach it. The
    # tenant-partitioned surface is the control plane above.
    assert h.client(tenant="acme", role=Role.VIEWER).get("/api/connectors").status_code == 200
    assert h.client(tenant="globex", role=Role.VIEWER).get("/api/connectors").status_code == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
