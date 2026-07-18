"""Security-hardening tests: SSRF guard on base_url + optional API auth."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maestro.connectors import ConnectorRegistry, StubConnector
from maestro.connectors.providers.custom import CustomConnector
from maestro.connectors.providers.http_base import assert_safe_base_url
from maestro.server.connectors_api import (
    API_TOKEN_ENV,
    LogStore,
    TestCaseStore,
    create_connectors_router,
)

# Async tests are auto-collected via asyncio_mode="auto"; the sync SSRF tests
# must not carry an asyncio mark, so no module-level pytestmark.


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata (link-local)
    "http://169.254.0.1/v1",                       # link-local
    "http://224.0.0.1/v1",                         # multicast
    "http://0.0.0.0/v1",                           # unspecified
])
def test_ssrf_guard_blocks_dangerous_ips(url):
    with pytest.raises(ValueError):
        assert_safe_base_url(url)


@pytest.mark.parametrize("url", [
    "http://localhost:11434",          # Ollama (hostname)
    "http://127.0.0.1:11434",          # loopback (legit local model)
    "http://192.168.1.10:8000/v1",     # private LAN (self-hosted)
    "https://api.openai.com/v1",       # public
    "https://x.example/v1",            # hostname
])
def test_ssrf_guard_allows_legitimate_hosts(url):
    assert_safe_base_url(url)  # must not raise


def test_custom_connector_construction_blocks_metadata_ip():
    with pytest.raises(ValueError):
        CustomConnector("x", "m", base_url="http://169.254.169.254/v1", api_key="k")


def test_ssrf_guard_env_override(monkeypatch):
    monkeypatch.setenv("MAESTRO_ALLOW_UNSAFE_HOSTS", "1")
    assert_safe_base_url("http://169.254.169.254/v1")  # override -> allowed


async def test_register_metadata_url_is_400(monkeypatch):
    reg = ConnectorRegistry()
    reg.register(StubConnector("stub"), default=True)
    app = FastAPI()
    app.include_router(create_connectors_router(reg, LogStore(), TestCaseStore()))
    with TestClient(app) as client:
        r = client.post("/api/connectors", json={
            "name": "evil", "provider": "custom", "model": "m",
            "base_url": "http://169.254.169.254/latest/meta-data/", "api_key": "k"})
        assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Optional API auth
# --------------------------------------------------------------------------- #
def _auth_app():
    reg = ConnectorRegistry()
    reg.register(StubConnector("stub"), default=True)
    app = FastAPI()
    app.include_router(create_connectors_router(reg, LogStore(), TestCaseStore()))
    return app


async def test_api_open_when_token_unset(monkeypatch):
    monkeypatch.delenv(API_TOKEN_ENV, raising=False)
    with TestClient(_auth_app()) as client:
        assert client.get("/api/connectors").status_code == 200


async def test_api_requires_token_when_set(monkeypatch):
    monkeypatch.setenv(API_TOKEN_ENV, "s3cret")
    with TestClient(_auth_app()) as client:
        assert client.get("/api/connectors").status_code == 401
        assert client.post("/api/chat", json={"prompt": "hi", "connector": "stub"}).status_code == 401
        ok = client.get("/api/connectors", headers={"authorization": "Bearer s3cret"})
        assert ok.status_code == 200


async def test_api_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv(API_TOKEN_ENV, "right")
    with TestClient(_auth_app()) as client:
        r = client.get("/api/connectors", headers={"authorization": "Bearer wrong"})
        assert r.status_code == 401
