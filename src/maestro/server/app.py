"""FastAPI + WebSocket backend (Sec 3.1, Sec 6.1 「FastAPI framework」).

Implements L4 Deployment & Infrastructure (Sec 4.1) and L7 Agent Ecosystem
operator dashboard (Sec 3.1). Provides:
- ``GET /``             : rendered dashboard HTML
- ``GET /risk``         : MAESTRO threat-risk matrix JSON (Table 4)
- ``GET /healthz``      : liveness probe
- ``WS  {{ ws_path }}`` : telemetry/alert/plan/risk stream (Sec 3.1)

Run with:
    uvicorn maestro.server.app:app --port 8000
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from ..config import load_config
from ..logging_setup import get_logger
from ..maestro.mapping import threat_risk_matrix
from ..maestro.threats import load_threats
from . import connectors_api
from .dashboard import DASHBOARD_HTML
from .playground import PLAYGROUND_HTML

logger = get_logger("maestro.server", log_file="results/run.log")


def create_app(cfg: Any = None) -> FastAPI:
    """Build the FastAPI app. ``cfg`` is an OmegaConf loaded by :mod:`maestro.config`."""
    if cfg is None:
        cfg = load_config()
    app = FastAPI(title="MAESTRO Network Monitoring Agent (repro of arXiv:2508.10043)")
    threats = load_threats()
    matrix = threat_risk_matrix(threats)

    # Model-connector testing dashboard + REST API (Deliverable 2).
    app.include_router(connectors_api.router)

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        return DASHBOARD_HTML.replace("{{ ws_path }}", cfg.server.ws_path)

    @app.get("/playground", response_class=HTMLResponse)
    def playground() -> str:
        return PLAYGROUND_HTML

    @app.get("/risk")
    def get_risk() -> JSONResponse:
        return JSONResponse({"matrix": matrix, "threats": len(threats)})

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "ts": time.time()})

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
    app.state.cfg = cfg
    app.state.matrix = matrix

    @app.websocket(cfg.server.ws_path)
    async def ws_endpoint(ws: WebSocket) -> None:
        await mgr.connect(ws)
        try:
            await ws.send_text(json.dumps({"kind": "risk", "matrix": matrix}))
            while True:
                await asyncio.sleep(cfg.server.dashboard_refresh_s)
                await mgr.broadcast({"kind": "telemetry",
                                     "ts": time.time(),
                                     "msg": "heartbeat (Sec 6.2 baseline every 7s)"})
        except WebSocketDisconnect:
            mgr.disconnect(ws)

    return app


# FastAPI-style `app` instance for `uvicorn maestro.server.app:app`
cfg = load_config()
app = create_app(cfg)
