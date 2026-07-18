"""Offline tests for the HTTP provider connectors using httpx.MockTransport.

No network and no API keys: every provider is exercised against a mock
transport that asserts the request shape and returns a canned response, so the
request-building and response-parsing paths are fully covered.
"""
from __future__ import annotations

import httpx
import pytest

from maestro.connectors import (
    AnthropicConnector,
    AuthenticationError,
    ChatRequest,
    CustomConnector,
    InvalidRequestError,
    OllamaConnector,
    OpenAIConnector,
    ProviderUnavailableError,
    RateLimitError,
)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- #
# OpenAI
# --------------------------------------------------------------------------- #
def test_openai_request_and_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = httpx.Request(request.method, request.url, content=request.content).content
        import json
        payload = json.loads(request.content)
        seen["payload"] = payload
        return httpx.Response(200, json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": "hi there"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3},
        })

    c = OpenAIConnector(api_key="sk-test", http_client=_client(handler))
    r = c.chat(ChatRequest.of("hello", system="be nice", temperature=0.2, max_tokens=50))
    assert r.text == "hi there"
    assert r.usage.prompt_tokens == 11 and r.usage.completion_tokens == 3
    assert r.finish_reason == "stop"
    assert seen["url"].endswith("/chat/completions")
    assert seen["auth"] == "Bearer sk-test"
    # system + user both forwarded in messages
    roles = [m["role"] for m in seen["payload"]["messages"]]
    assert roles == ["system", "user"]
    assert seen["payload"]["max_tokens"] == 50


@pytest.mark.parametrize("code,exc", [
    (401, AuthenticationError),
    (403, AuthenticationError),
    (429, RateLimitError),
    (500, ProviderUnavailableError),
    (400, InvalidRequestError),
])
def test_openai_error_mapping(code, exc):
    def handler(request):
        return httpx.Response(code, json={"error": "nope"})

    c = OpenAIConnector(api_key="k", http_client=_client(handler))
    with pytest.raises(exc):
        c.chat(ChatRequest.of("hi"))


def test_connect_error_maps_to_unavailable():
    def handler(request):
        raise httpx.ConnectError("refused")

    c = OpenAIConnector(api_key="k", http_client=_client(handler))
    with pytest.raises(ProviderUnavailableError):
        c.chat(ChatRequest.of("hi"))


def test_rate_limit_is_retryable_flag():
    def handler(request):
        return httpx.Response(429)

    c = OpenAIConnector(api_key="k", http_client=_client(handler))
    with pytest.raises(RateLimitError) as ei:
        c.chat(ChatRequest.of("hi"))
    assert ei.value.retryable is True


# --------------------------------------------------------------------------- #
# Anthropic
# --------------------------------------------------------------------------- #
def test_anthropic_request_and_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["headers"] = request.headers
        seen["payload"] = json.loads(request.content)
        return httpx.Response(200, json={
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "assessment: throttle"}],
            "usage": {"input_tokens": 20, "output_tokens": 4},
            "stop_reason": "end_turn",
        })

    c = AnthropicConnector(api_key="ak", http_client=_client(handler))
    r = c.chat(ChatRequest.of("classify", system="you are an agent", max_tokens=64))
    assert r.text == "assessment: throttle"
    assert r.usage.prompt_tokens == 20 and r.usage.completion_tokens == 4
    assert r.finish_reason == "end_turn"
    # Anthropic-specific headers + system split out of messages
    assert seen["headers"]["x-api-key"] == "ak"
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert seen["payload"]["system"] == "you are an agent"
    assert all(m["role"] != "system" for m in seen["payload"]["messages"])
    # sampling params are NOT forwarded by default (rejected by modern models)
    assert "temperature" not in seen["payload"]


def test_anthropic_url_path():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "x"}],
                                         "usage": {"input_tokens": 1, "output_tokens": 1}})

    AnthropicConnector(api_key="k", http_client=_client(handler)).chat(ChatRequest.of("hi"))
    assert seen["url"].endswith("/v1/messages")


# --------------------------------------------------------------------------- #
# Ollama (local, no auth)
# --------------------------------------------------------------------------- #
def test_ollama_request_and_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["payload"] = json.loads(request.content)
        return httpx.Response(200, json={
            "model": "llama3",
            "message": {"role": "assistant", "content": "local reply"},
            "prompt_eval_count": 7, "eval_count": 2, "done": True,
        })

    c = OllamaConnector(http_client=_client(handler))
    r = c.chat(ChatRequest.of("hi"))
    assert r.text == "local reply"
    assert r.usage.prompt_tokens == 7 and r.usage.completion_tokens == 2
    assert r.provider == "ollama"
    assert seen["url"].endswith("/api/chat")
    assert seen["auth"] is None  # no auth for local
    assert seen["payload"]["stream"] is False


# --------------------------------------------------------------------------- #
# Custom (configurable auth header)
# --------------------------------------------------------------------------- #
def test_custom_uses_custom_auth_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["x-api-key"] = request.headers.get("x-api-key")
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        })

    c = CustomConnector("my", "m", base_url="https://x.example/v1", api_key="secret",
                        auth_header="x-api-key", http_client=_client(handler))
    c.chat(ChatRequest.of("hi"))
    assert seen["x-api-key"] == "secret"
    assert seen["authorization"] is None


def test_custom_defaults_to_bearer():
    seen = {}

    def handler(request):
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}],
                                         "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    CustomConnector("my", "m", base_url="https://x/v1", api_key="tok",
                    http_client=_client(handler)).chat(ChatRequest.of("hi"))
    assert seen["authorization"] == "Bearer tok"


def test_non_json_response_raises_connector_error():
    from maestro.connectors import ConnectorError

    def handler(request):
        return httpx.Response(200, text="not json")

    c = OpenAIConnector(api_key="k", http_client=_client(handler))
    with pytest.raises(ConnectorError):
        c.chat(ChatRequest.of("hi"))
