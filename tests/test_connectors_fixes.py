"""Regression tests for the code-review fixes on the connector system."""
from __future__ import annotations

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maestro.connectors import (
    AnthropicConnector,
    ChatRequest,
    ConnectorRegistry,
    StubConnector,
    build_registry,
)
from maestro.connectors.base import GenerationResult, ModelConnector, Usage
from maestro.server.connectors_api import (
    LogStore,
    TestCaseStore,
    create_connectors_router,
)

# Async tests below are auto-collected via asyncio_mode="auto"; the sync tests
# in this module must not carry an asyncio mark, so no module-level pytestmark.


def _app():
    reg = ConnectorRegistry()
    reg.register(StubConnector("stub"), default=True)
    app = FastAPI()
    app.include_router(create_connectors_router(reg, LogStore(), TestCaseStore()))
    return app, reg


# Fix 1 — compare mode is resilient to an unknown connector name
async def test_compare_with_unknown_name_returns_per_connector_error():
    app, _ = _app()
    with TestClient(app) as client:
        r = client.post("/api/chat", json={"prompt": "hi", "compare": ["stub", "ghost"]})
        assert r.status_code == 200
        results = {res["connector"]: res for res in r.json()["results"]}
        assert results["stub"]["ok"] is True
        assert results["ghost"]["ok"] is False
        assert results["ghost"]["error"]["type"] == "NotFound"


# ...but a single unknown target still 404s (caller named one bad connector)
async def test_single_unknown_name_still_404():
    app, _ = _app()
    with TestClient(app) as client:
        assert client.post("/api/chat", json={"prompt": "hi", "connector": "ghost"}).status_code == 404


# Fix 2 — registering a custom provider without base_url is a 400, not a 500
async def test_register_custom_without_base_url_is_400():
    app, _ = _app()
    with TestClient(app) as client:
        r = client.post("/api/connectors", json={
            "name": "bad", "provider": "custom", "model": "m"})
        assert r.status_code == 400


# Fix 3 — an empty connectors config never yields a stub-less registry
def test_build_registry_empty_config_falls_back_to_stub(tmp_path):
    yaml = tmp_path / "connectors.yaml"
    yaml.write_text("connectors: []\n", encoding="utf-8")
    reg = build_registry(yaml)
    assert reg.default_name == "stub"
    assert reg.resolve().provider == "stub"


# Fix 4 — a disabled first-registered connector does not become the default
def test_disabled_first_connector_is_not_default():
    reg = ConnectorRegistry()
    reg.register(StubConnector("a", enabled=False))
    reg.register(StubConnector("b"))  # first enabled -> default
    assert reg.default_name == "b"
    assert reg.resolve().name == "b"


# Fix 5 — remove() closes a connector's owned HTTP client without raising
def test_remove_closes_client():
    closed = {"n": 0}

    class _Tracking(ModelConnector):
        provider = "track"

        def _generate(self, request, model):
            return GenerationResult(text="x", model=model)

        def close(self):
            closed["n"] += 1

    reg = ConnectorRegistry()
    reg.register(_Tracking("t", "m"))
    reg.remove("t")
    assert closed["n"] == 1


# Fix 6 — per-field usage estimation (provider reports completion only)
def test_usage_estimates_missing_prompt_tokens():
    class CompletionOnly(ModelConnector):
        provider = "co"

        def _generate(self, request, model):
            return GenerationResult(text="a reply", model=model,
                                    usage=Usage(prompt_tokens=0, completion_tokens=7))

    r = CompletionOnly("c", "m").chat(ChatRequest.of("a real prompt with words"))
    assert r.usage.completion_tokens == 7        # measured value preserved
    assert r.usage.prompt_tokens > 0             # missing prompt tokens estimated
    assert r.usage.estimated is True


# Fix 7 — Anthropic forwards sampling params only when opted in
def _mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_anthropic_forward_sampling_opt_in():
    seen = {}

    def handler(request):
        import json
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"content": [{"type": "text", "text": "x"}],
                                         "usage": {"input_tokens": 1, "output_tokens": 1}})

    # default: temperature dropped
    AnthropicConnector(api_key="k", http_client=_mock(handler)).chat(
        ChatRequest.of("hi", temperature=0.9))
    assert "temperature" not in seen

    # opt-in: temperature forwarded
    seen.clear()
    AnthropicConnector(api_key="k", forward_sampling=True, http_client=_mock(handler)).chat(
        ChatRequest.of("hi", temperature=0.9))
    assert seen["temperature"] == 0.9
