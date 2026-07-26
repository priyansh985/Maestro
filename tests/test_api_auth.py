"""Adversarial tests for the zero-trust API boundary (CTRL-L4-03 / CTRL-L4-07).

These are the *bypass* tests that let CTRL-L4-03 be graded ``verified`` rather
than merely ``implemented``: an unauthenticated, malformed, forged, expired,
revoked, cross-tenant, or under-privileged caller must be denied at the door,
fail-closed, before it can touch the live enforcement stack. BP3.2 extends the
same proof over the model-testing/connectors API and adds per-principal rate
limiting (CTRL-L4-07).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from maestro.server.app import create_app
from maestro.server.auth import (
    AuthError,
    AuthService,
    RateLimiter,
    Role,
    configure_auth,
)
from maestro.server.control_api import _PLANES


@dataclass
class Harness:
    app: object
    svc: AuthService

    def client(self, token: str | None = None) -> TestClient:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return TestClient(self.app, headers=headers)

    def token(
        self,
        *,
        role: Role = Role.OPERATOR,
        tenant: str = "default",
        ttl_seconds: float = 3600.0,
        now: float | None = None,
        jti: str | None = None,
    ) -> str:
        return self.svc.issue(
            "svc:test", tenant=tenant, role=role,
            ttl_seconds=ttl_seconds, now=now, jti=jti,
        )


@pytest.fixture
def h() -> Harness:
    app = create_app()  # configures auth from config (enforce=True)
    svc = AuthService(key=b"unit-auth-key")
    configure_auth(enforce=True, service=svc, control_plane_tenant="default")
    _PLANES.clear()  # isolated per-tenant control planes; start each test clean
    return Harness(app, svc)


# --- authentication: fail closed on every bad credential ------------------- #
def test_unauthenticated_request_is_denied(h: Harness) -> None:
    assert h.client().get("/api/controls").status_code == 401


def test_malformed_token_is_denied(h: Harness) -> None:
    assert h.client("not-a-real-token").get("/api/controls").status_code == 401


def test_forged_signature_is_denied(h: Harness) -> None:
    valid = h.token(role=Role.ADMIN)
    tampered = valid[:-1] + ("0" if valid[-1] != "0" else "1")
    assert h.client(tampered).get("/api/controls").status_code == 401


def test_tampered_payload_is_denied(h: Harness) -> None:
    # Flip a byte in the payload half; the signature no longer matches.
    valid = h.token(role=Role.VIEWER)
    payload, sig = valid.split(".", 1)
    forged = (payload[:-1] + ("A" if payload[-1] != "A" else "B")) + "." + sig
    assert h.client(forged).get("/api/controls").status_code == 401


def test_expired_token_is_denied(h: Harness) -> None:
    stale = h.token(role=Role.ADMIN, ttl_seconds=1.0, now=time.time() - 10_000)
    assert h.client(stale).get("/api/controls").status_code == 401


def test_revoked_token_is_denied(h: Harness) -> None:
    tok = h.token(role=Role.ADMIN, jti="revoke-me")
    assert h.client(tok).get("/api/controls").status_code == 200  # valid before
    h.svc.revoke("revoke-me")
    assert h.client(tok).get("/api/controls").status_code == 401  # denied after


# --- authorization: RBAC + tenant confinement ------------------------------ #
def test_viewer_can_read_but_cannot_mutate(h: Harness) -> None:
    viewer = h.client(h.token(role=Role.VIEWER))
    assert viewer.get("/api/controls").status_code == 200
    assert viewer.post("/api/alert", json={"cls": "dos"}).status_code == 403


def test_operator_can_mutate_but_cannot_reset(h: Harness) -> None:
    operator = h.client(h.token(role=Role.OPERATOR))
    assert operator.post("/api/alert", json={"cls": "dos"}).status_code == 200
    assert operator.post("/api/reset", json={"shadow": False}).status_code == 403


def test_admin_can_reset(h: Harness) -> None:
    admin = h.client(h.token(role=Role.ADMIN))
    assert admin.post("/api/reset", json={"shadow": False}).status_code == 200


# (Tenant confinement is no longer a single-tenant equality check — it is
# structural per-tenant isolation, proven adversarially in test_tenant_isolation.py.)


# --- public surface stays reachable ---------------------------------------- #
def test_healthz_is_public(h: Harness) -> None:
    assert h.client().get("/healthz").status_code == 200


def test_control_panel_html_is_public(h: Harness) -> None:
    # The static shell loads unauthenticated; its /api/* data calls do not.
    assert h.client().get("/control").status_code == 200


# --- disabling enforcement restores the paper's baseline exactly ----------- #
def test_disabling_enforcement_allows_anonymous(h: Harness) -> None:
    configure_auth(enforce=False, service=h.svc, control_plane_tenant="default")
    try:
        assert h.client().get("/api/controls").status_code == 200
        assert h.client().post("/api/reset", json={"shadow": False}).status_code == 200
    finally:
        configure_auth(enforce=True, service=h.svc, control_plane_tenant="default")


# --- BP3.2: the connectors / model-testing API is under the same boundary --- #
def test_connectors_api_requires_authentication(h: Harness) -> None:
    assert h.client().get("/api/connectors").status_code == 401


def test_viewer_can_list_connectors_but_cannot_chat(h: Harness) -> None:
    viewer = h.client(h.token(role=Role.VIEWER))
    assert viewer.get("/api/connectors").status_code == 200
    # POST /api/chat is a mutation (runs a model + writes a log) → needs OPERATOR.
    assert viewer.post("/api/chat", json={"prompt": "hi"}).status_code == 403


def test_operator_can_chat_on_the_connectors_api(h: Harness) -> None:
    operator = h.client(h.token(role=Role.OPERATOR))
    resp = operator.post("/api/chat", json={"prompt": "hi"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "single"


# --- BP3.2: per-principal rate limiting (CTRL-L4-07) ----------------------- #
def test_exhausted_rate_limit_returns_429(h: Harness) -> None:
    # A tiny, non-refilling bucket: the third request for this principal is denied.
    limiter = RateLimiter(capacity=2, refill_per_sec=0.0)
    configure_auth(enforce=True, service=h.svc,
                   control_plane_tenant="default", rate_limiter=limiter)
    try:
        viewer = h.client(h.token(role=Role.VIEWER))
        assert viewer.get("/api/controls").status_code == 200
        assert viewer.get("/api/controls").status_code == 200
        assert viewer.get("/api/controls").status_code == 429  # bucket empty
    finally:
        configure_auth(enforce=True, service=h.svc, control_plane_tenant="default")


def test_rate_limiter_bucket_exhausts_and_refills() -> None:
    rl = RateLimiter(capacity=2, refill_per_sec=1.0)
    assert rl.allow("p", now=0.0) is True
    assert rl.allow("p", now=0.0) is True
    assert rl.allow("p", now=0.0) is False   # bucket empty
    assert rl.allow("p", now=1.0) is True    # one token refilled after 1s
    assert rl.allow("q", now=0.0) is True    # a different principal is independent


def test_rate_limiter_per_minute_factory() -> None:
    assert RateLimiter.per_minute(0) is None
    assert RateLimiter.per_minute(-5) is None
    rl = RateLimiter.per_minute(60)
    assert rl is not None
    assert rl.capacity == 60.0
    assert abs(rl.refill_per_sec - 1.0) < 1e-9


def test_rate_limiter_nonpositive_capacity_is_unlimited() -> None:
    rl = RateLimiter(capacity=0, refill_per_sec=0.0)
    assert all(rl.allow("p", now=float(i)) for i in range(10))


# --- AuthService unit behavior --------------------------------------------- #
def test_token_round_trips_to_its_principal() -> None:
    svc = AuthService(key=b"k")
    tok = svc.issue("user:priyansh", tenant="acme", role=Role.OPERATOR, kind="user")
    p = svc.authenticate(tok)
    assert (p.subject, p.tenant, p.role, p.kind) == (
        "user:priyansh", "acme", Role.OPERATOR, "user")


def test_authenticate_rejects_a_token_signed_with_another_key() -> None:
    tok = AuthService(key=b"key-a").issue("svc:x", role=Role.ADMIN)
    with pytest.raises(AuthError):
        AuthService(key=b"key-b").authenticate(tok)


def test_role_ordering_is_total() -> None:
    assert Role.VIEWER < Role.OPERATOR < Role.ADMIN


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
