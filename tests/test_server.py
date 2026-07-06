"""Forward-pass sanity tests for the FastAPI app (Sec 3.1 backend)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_app_has_routes():
    from maestro.server.app import create_app
    from maestro.config import load_config

    cfg = load_config()
    app = create_app(cfg)
    routes = {r.path for r in app.routes}
    assert "/" in routes
    assert "/risk" in routes
    assert "/healthz" in routes
    assert cfg.server.ws_path in routes


async def test_healthz_returns_ok():
    from fastapi.testclient import TestClient

    from maestro.server.app import create_app
    from maestro.config import load_config
    app = create_app(load_config())
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


async def test_risk_matrix_endpoint():
    from fastapi.testclient import TestClient

    from maestro.server.app import create_app
    from maestro.config import load_config
    app = create_app(load_config())
    with TestClient(app) as client:
        r = client.get("/risk")
        assert r.status_code == 200
        body = r.json()
        assert body["threats"] == 10
        assert len(body["matrix"]) == 10
        # Threat 7 -> highest risk score 27
        sec7 = next(r for r in body["matrix"]
                    if r["Threat"].startswith("7."))
        assert sec7["Risk Score"] == 27
