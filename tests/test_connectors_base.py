"""Tests for the connector base layer: value objects, timing, usage, errors."""
from __future__ import annotations

import pytest

from maestro.connectors import (
    ChatMessage,
    ChatRequest,
    ConnectorError,
    Role,
    StubConnector,
    Usage,
    estimate_tokens,
)
from maestro.connectors.base import GenerationResult, ModelConnector


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("x" * 40) == 10


def test_usage_total_and_dict():
    u = Usage(prompt_tokens=3, completion_tokens=5)
    assert u.total_tokens == 8
    assert u.to_dict()["total_tokens"] == 8


def test_chatrequest_system_split():
    req = ChatRequest(messages=[
        ChatMessage(Role.SYSTEM, "sys-a"),
        ChatMessage(Role.SYSTEM, "sys-b"),
        ChatMessage(Role.USER, "hello"),
    ])
    assert req.system_prompt() == "sys-a\n\nsys-b"
    assert [m.content for m in req.non_system_messages()] == ["hello"]


def test_chatrequest_of_builder():
    req = ChatRequest.of("hi", system="be nice", temperature=0.1, max_tokens=5)
    assert req.system_prompt() == "be nice"
    assert req.params.temperature == 0.1
    assert req.params.max_tokens == 5


def test_stub_chat_is_deterministic_with_metrics():
    sc = StubConnector()
    r1 = sc.chat(ChatRequest.of("hello", system="s"))
    r2 = sc.chat(ChatRequest.of("hello", system="s"))
    assert r1.text == r2.text
    assert r1.provider == "stub"
    assert r1.connector == "stub"
    assert r1.usage.total_tokens > 0
    assert r1.latency_ms >= 0
    assert r1.to_dict()["provider"] == "stub"


def test_disabled_connector_raises():
    sc = StubConnector()
    sc.enabled = False
    with pytest.raises(ConnectorError):
        sc.chat(ChatRequest.of("hi"))


def test_usage_estimated_when_provider_reports_none():
    class NoUsage(ModelConnector):
        provider = "nousage"

        def _generate(self, request, model):
            return GenerationResult(text="some reply text here", model=model, usage=None)

    r = NoUsage("n", "m").chat(ChatRequest.of("a longer prompt to estimate"))
    assert r.usage.estimated is True
    assert r.usage.completion_tokens > 0


def test_unexpected_error_is_normalized():
    class Boom(ModelConnector):
        provider = "boom"

        def _generate(self, request, model):
            raise RuntimeError("kaboom")

    with pytest.raises(ConnectorError) as ei:
        Boom("b", "m").chat(ChatRequest.of("hi"))
    assert "kaboom" in str(ei.value)


def test_request_model_override():
    sc = StubConnector(model="default-model")
    r = sc.chat(ChatRequest(messages=[ChatMessage(Role.USER, "hi")], model="override-model"))
    assert r.model == "override-model"
