"""Tests for FallbackConnector graceful-degradation logic."""
from __future__ import annotations

import pytest

from maestro.connectors import (
    ChatRequest,
    ConnectorError,
    FallbackConnector,
    InvalidRequestError,
    ProviderUnavailableError,
    RateLimitError,
    StubConnector,
)
from maestro.connectors.base import GenerationResult, ModelConnector


class _Failing(ModelConnector):
    """Connector that always raises the given error."""

    provider = "failing"

    def __init__(self, name, error: ConnectorError):
        super().__init__(name, "m")
        self.error = error

    def _generate(self, request, model) -> GenerationResult:
        raise self.error


def test_fallback_uses_next_on_retryable():
    primary = _Failing("p", ProviderUnavailableError("down", provider="p"))
    fb = FallbackConnector("fb", [primary, StubConnector("backup")])
    r = fb.chat(ChatRequest.of("hi"))
    assert r.connector == "backup"


def test_fallback_records_hook():
    events = []
    primary = _Failing("p", RateLimitError("429", provider="p"))
    fb = FallbackConnector("fb", [primary, StubConnector("backup")],
                           on_fallback=lambda c, e: events.append((c.name, type(e).__name__)))
    fb.chat(ChatRequest.of("hi"))
    assert events == [("p", "RateLimitError")]


def test_fallback_non_retryable_raises_immediately():
    primary = _Failing("p", InvalidRequestError("bad", provider="p"))
    backup = StubConnector("backup")
    fb = FallbackConnector("fb", [primary, backup])
    with pytest.raises(InvalidRequestError):
        fb.chat(ChatRequest.of("hi"))


def test_fallback_skips_disabled():
    disabled = StubConnector("disabled")
    disabled.enabled = False
    working = StubConnector("working")
    fb = FallbackConnector("fb", [disabled, working])
    assert fb.chat(ChatRequest.of("hi")).connector == "working"


def test_fallback_all_fail_raises_last():
    a = _Failing("a", ProviderUnavailableError("a-down", provider="a"))
    b = _Failing("b", ProviderUnavailableError("b-down", provider="b"))
    fb = FallbackConnector("fb", [a, b])
    with pytest.raises(ProviderUnavailableError) as ei:
        fb.chat(ChatRequest.of("hi"))
    assert "b-down" in str(ei.value)


def test_fallback_requires_connectors():
    with pytest.raises(ValueError):
        FallbackConnector("fb", [])


def test_fallback_describe_lists_chain():
    fb = FallbackConnector("fb", [StubConnector("a"), StubConnector("b")])
    assert fb.describe()["chain"] == ["a", "b"]
