"""Tests for the connector-backed reasoner (framework integration)."""
from __future__ import annotations

import httpx

from maestro.agent.reasoning import (
    ConnectorReasoner,
    ReasoningResult,
    get_reasoner,
    reasoner_from_registry,
)
from maestro.connectors import OpenAIConnector, StubConnector
from maestro.telemetry.detection import Alert, AlertClass


def _alert(cls: AlertClass, sev: float = 0.9) -> Alert:
    return Alert(ts=0.0, cls=cls, severity=sev, detail="flood detected")


def test_connector_reasoner_maps_alert_to_action():
    r = ConnectorReasoner(StubConnector())
    out = r.reason(_alert(AlertClass.DOS))
    assert isinstance(out, ReasoningResult)
    assert out.action == "throttle_telemetry"  # deterministic, within L3 allow-list
    assert out.summary  # comes from the connector response
    assert out.severity == 0.9


def test_connector_reasoner_action_per_class():
    r = ConnectorReasoner(StubConnector())
    assert r.reason(_alert(AlertClass.ANOMALY)).action == "raise_thresholds"
    assert r.reason(_alert(AlertClass.NORMAL, 0.1)).action == "noop"


def test_connector_reasoner_over_mocked_openai():
    """The agent's reasoning step runs through the connector, backend-agnostic."""
    def handler(request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Saturation detected; throttle."}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4}})

    conn = OpenAIConnector(api_key="k",
                           http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    out = ConnectorReasoner(conn).reason(_alert(AlertClass.DOS))
    assert out.summary == "Saturation detected; throttle."
    assert out.action == "throttle_telemetry"


def test_get_reasoner_connector_provider():
    conn = StubConnector()
    r = get_reasoner(provider="connector", connector=conn)
    assert isinstance(r, ConnectorReasoner)
    assert r.reason(_alert(AlertClass.DOS)).action == "throttle_telemetry"


def test_reasoner_from_registry_default_is_offline_stub():
    r = reasoner_from_registry()
    out = r.reason(_alert(AlertClass.DOS))
    assert out.action == "throttle_telemetry"
    assert out.summary
