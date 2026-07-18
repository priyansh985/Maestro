"""Tests for the /api model-testing router via FastAPI TestClient (offline)."""
from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maestro.connectors import ConnectorRegistry, StubConnector
from maestro.server.connectors_api import (
    LogStore,
    TestCaseStore,
    create_connectors_router,
)

pytestmark = pytest.mark.asyncio


def _app() -> tuple[FastAPI, ConnectorRegistry, LogStore, TestCaseStore]:
    reg = ConnectorRegistry()
    reg.register(StubConnector("stub"), default=True)
    reg.register(StubConnector("stub2"))
    logs, cases = LogStore(), TestCaseStore()
    app = FastAPI()
    app.include_router(create_connectors_router(reg, logs, cases))
    return app, reg, logs, cases


async def test_list_connectors():
    app, *_ = _app()
    with TestClient(app) as client:
        body = client.get("/api/connectors").json()
        assert body["default"] == "stub"
        names = {c["name"] for c in body["connectors"]}
        assert names == {"stub", "stub2"}


async def test_chat_single_and_logs():
    app, _reg, logs, _cases = _app()
    with TestClient(app) as client:
        r = client.post("/api/chat", json={"prompt": "hello", "connector": "stub"}).json()
        assert r["mode"] == "single"
        res = r["results"][0]
        assert res["ok"] is True
        assert res["response"]["provider"] == "stub"
        assert "latency_ms" in res["response"]
        assert res["response"]["usage"]["total_tokens"] > 0
        assert "log_id" in res
        # log recorded
        logs_body = client.get("/api/logs").json()
        assert len(logs_body["logs"]) == 1


async def test_chat_compare_side_by_side():
    app, *_ = _app()
    with TestClient(app) as client:
        r = client.post("/api/chat", json={
            "prompt": "hi", "compare": ["stub", "stub2"]}).json()
        assert r["mode"] == "compare"
        assert {res["connector"] for res in r["results"]} == {"stub", "stub2"}


async def test_chat_unknown_connector_404():
    app, *_ = _app()
    with TestClient(app) as client:
        resp = client.post("/api/chat", json={"prompt": "hi", "connector": "ghost"})
        assert resp.status_code == 404


async def test_register_custom_connector_then_use():
    """Register a custom provider whose HTTP client is mocked, then call it."""
    app, reg, *_ = _app()

    def handler(request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "custom says hi"}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3}})

    with TestClient(app) as client:
        resp = client.post("/api/connectors", json={
            "name": "myprov", "provider": "custom", "model": "m",
            "base_url": "https://x.example/v1", "api_key": "k"})
        assert resp.status_code == 200
        # Inject a mock transport so the live call stays offline.
        reg.get("myprov")._client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[attr-defined]
        r = client.post("/api/chat", json={"prompt": "hi", "connector": "myprov"}).json()
        assert r["results"][0]["ok"] is True
        assert r["results"][0]["response"]["text"] == "custom says hi"


async def test_enable_disable_and_default():
    app, reg, *_ = _app()
    with TestClient(app) as client:
        client.post("/api/connectors/stub2/disable")
        assert reg.get("stub2").enabled is False
        client.post("/api/connectors/stub2/enable")
        assert reg.get("stub2").enabled is True
        client.post("/api/connectors/stub2/default")
        assert reg.default_name == "stub2"


async def test_health_endpoint():
    app, *_ = _app()
    with TestClient(app) as client:
        assert client.post("/api/connectors/stub/health").json()["ok"] is True


async def test_verify_log_checkmark():
    app, *_ = _app()
    with TestClient(app) as client:
        r = client.post("/api/chat", json={"prompt": "hi", "connector": "stub"}).json()
        log_id = r["results"][0]["log_id"]
        v = client.post(f"/api/logs/{log_id}/verify", json={"verified": True}).json()
        assert v["log"]["verified"] is True


async def test_testcase_save_replay_delete():
    app, *_ = _app()
    with TestClient(app) as client:
        saved = client.post("/api/testcases", json={
            "name": "greeting", "prompt": "hello", "connector": "stub"}).json()
        cid = saved["testcase"]["id"]
        assert client.get("/api/testcases").json()["testcases"]
        replay = client.post(f"/api/testcases/{cid}/replay").json()
        assert replay["results"][0]["ok"] is True
        assert client.delete(f"/api/testcases/{cid}").json()["removed"] == cid
        assert client.get("/api/testcases").json()["testcases"] == []


async def test_fallback_mode_runs_through_chain():
    """fallback=True routes through a FallbackConnector and returns a response."""
    app, *_ = _app()
    with TestClient(app) as client:
        r = client.post("/api/chat", json={
            "prompt": "hi", "connector": "stub", "fallback": True}).json()
        assert r["mode"] == "fallback"
        assert r["results"][0]["ok"] is True
        assert r["results"][0]["via_fallback"] is True
