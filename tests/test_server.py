"""Forward-pass sanity tests for the FastAPI app (Sec 3.1 backend)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_app_has_routes():
    from maestro.config import load_config
    from maestro.server.app import create_app

    cfg = load_config()
    app = create_app(cfg)
    # Newer Starlette inserts _IncludedRouter markers into app.routes; only
    # concrete routes carry .path.
    routes = {r.path for r in app.routes if hasattr(r, "path")}
    assert "/" in routes
    assert "/risk" in routes
    assert "/healthz" in routes
    assert cfg.server.ws_path in routes


async def test_healthz_returns_ok():
    from fastapi.testclient import TestClient

    from maestro.config import load_config
    from maestro.server.app import create_app
    app = create_app(load_config())
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


async def test_risk_matrix_endpoint():
    from fastapi.testclient import TestClient

    from maestro.config import load_config
    from maestro.server.app import create_app
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


async def test_dashboard_spa_served_with_all_sections():
    from fastapi.testclient import TestClient

    from maestro.config import load_config
    from maestro.server.app import create_app
    app = create_app(load_config())
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        html = r.text
        # Every management surface is present in the SPA shell
        for section in ("overview", "agents", "memory", "ledger",
                        "controls", "policies", "tenants", "metrics"):
            assert f'id="sec-{section}"' in html, section
        # The live surface the SPA drives
        for fn in ("openCreateAgent", "openAgent", "agentAlert", "promoteRecord",
                   "verifyLedger", "validatePolicy", "confirmIsolate", "loadMetrics"):
            assert fn in html, fn
        # Zero-trust token UX (same contract as the playground)
        assert "maestro_token" in html
