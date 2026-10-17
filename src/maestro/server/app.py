"""FastAPI + WebSocket backend (Sec 3.1, Sec 6.1 「FastAPI framework」).

Implements L4 Deployment & Infrastructure (Sec 4.1) and L7 Agent Ecosystem
operator dashboard (Sec 3.1). Provides:
- ``GET /``             : rendered dashboard HTML
- ``GET /risk``         : MAESTRO threat-risk matrix JSON (Table 4)
- ``GET /healthz``      : liveness probe
- ``WS  /ws``           : telemetry/alert/plan/risk stream (Sec 3.1)

The control-plane REST API itself lives in ``control_api`` (``/api/...``);
this module adds the HTML shells, the dashboard surfaces, and the WebSocket.

Run with:
    uvicorn maestro.server.app:app --port 8000
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import time
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from ..config import cfg_get, load_config
from ..logging_setup import get_logger
from ..maestro.mapping import threat_risk_matrix
from ..maestro.threats import load_threats
from . import agents_api, connectors_api, control_api
from .auth import DEFAULT_CONTROL_PLANE_TENANT, RateLimiter, configure_auth
from .control_panel import CONTROL_PANEL_HTML
from .dashboards.dashboard import DASHBOARD_HTML
from .playground import PLAYGROUND_HTML

logger = get_logger("maestro.server", log_file="results/run.log")


def create_app(cfg: Any = None) -> FastAPI:
    """Build the FastAPI app. ``cfg`` is an OmegaConf loaded by :mod:`maestro.config`."""
    if cfg is None:
        cfg = load_config()
    app = FastAPI(title="MAESTRO Network Monitoring Agent (repro of arXiv:2508.10043)")
    threats = load_threats()
    matrix = threat_risk_matrix(threats)

    # Zero-trust boundary for the whole /api surface (control plane + model
    # testing; CTRL-L4-03). Default-on; setting mitigation.zero_trust_api=false
    # restores the paper's unauthenticated baseline.
    configure_auth(
        enforce=bool(cfg_get(cfg, "mitigation.zero_trust_api", True)),
        control_plane_tenant=DEFAULT_CONTROL_PLANE_TENANT,
        rate_limiter=RateLimiter.per_minute(
            float(cfg_get(cfg, "mitigation.api_rate_limit_per_min", 120))
        ),
    )

    # Model-connector testing dashboard + REST API (Deliverable 2).
    app.include_router(connectors_api.router)
    # Control-plane REST API driving the live enforcement stack (blueprint §3).
    app.include_router(control_api.router)
    # Fleet management: create/drive/stop the tenant's agents (BP11).
    app.include_router(agents_api.router)

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        return DASHBOARD_HTML

    @app.get("/control", response_class=HTMLResponse)
    def control_panel() -> str:
        return CONTROL_PANEL_HTML

    @app.get("/playground", response_class=HTMLResponse)
    def playground() -> str:
        return PLAYGROUND_HTML

    @app.get("/risk")
    def get_risk() -> JSONResponse:
        return JSONResponse({"matrix": matrix, "threats": len(threats)})

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "ts": time.time()})

    # --------------------------------------------------------------------------- #
    # WebSocket endpoint: live telemetry/alert/plan stream for the dashboard
    # (Sec 3.1 interactive monitoring loop).
    # --------------------------------------------------------------------------- #

    class ConnectionManager:
        def __init__(self) -> None:
            self.active: list[WebSocket] = []

        async def connect(self, ws: WebSocket) -> None:
            await ws.accept()
            self.active.append(ws)

        def disconnect(self, ws: WebSocket) -> None:
            if ws in self.active:
                self.active.remove(ws)

        async def broadcast(self, msg: dict) -> None:
            text = json.dumps(msg)
            for ws in list(self.active):
                try:
                    await ws.send_text(text)
                except Exception:
                    self.active.remove(ws)

    mgr = ConnectionManager()
    app.state.mgr = mgr

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await mgr.connect(ws)
        with contextlib.suppress(Exception):
            await ws.send_text(json.dumps({
                "kind": "state",
                "tenant": DEFAULT_CONTROL_PLANE_TENANT,
                "ts": time.time(),
            }))
        try:
            while True:
                await asyncio.sleep(5)
                await mgr.broadcast({"kind": "telemetry", "ts": time.time(),
                                    "msg": "heartbeat (Sec 6.2 baseline every 7s)"})
        except WebSocketDisconnect:
            mgr.disconnect(ws)

    return app


# FastAPI-style `app` instance for `uvicorn maestro.server.app:app`
cfg = load_config()
app = create_app(cfg)