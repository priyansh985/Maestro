"""Tests for the LLM reasoning engine stub + provider factory (Sec 3.1 L1)."""
from __future__ import annotations

import pytest

from maestro.agent.reasoning import ReasoningResult, StubReasoner, get_reasoner
from maestro.telemetry.detection import Alert, AlertClass


def _alert(cls: AlertClass, sev: float = 0.9) -> Alert:
    return Alert(ts=0.0, cls=cls, severity=sev, detail="test")


def test_stub_actions_per_alert_class():
    r = StubReasoner()
    assert r.reason(_alert(AlertClass.DOS)).action == "throttle_telemetry"
    assert r.reason(_alert(AlertClass.ANOMALY)).action == "raise_thresholds"
    out = r.reason(_alert(AlertClass.NORMAL))
    assert out.action == "noop"
    assert isinstance(out, ReasoningResult)


def test_get_reasoner_stub_is_default():
    r = get_reasoner()
    assert isinstance(r, StubReasoner)
    assert get_reasoner(provider="stub") is not None


def test_get_reasoner_unknown_provider_raises():
    with pytest.raises(ValueError):
        get_reasoner(provider="totally-not-a-provider")


def test_get_reasoner_openai_requires_key(monkeypatch):
    """Without an API key the OpenAI path must fail cleanly (ImportError if the
    optional dep is absent, RuntimeError if present but key missing)."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises((RuntimeError, ImportError)):
        get_reasoner(provider="openai")
