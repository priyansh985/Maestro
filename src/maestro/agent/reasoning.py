"""LLM Reasoning Engine (Sec 3.1 L1 + control loop).

The paper uses ``pydantic-ai`` + an LLM (Sec 6.1) with domain prompts (Sec
6.1). To keep the reproduction offline + deterministic we ship a
``stub`` provider (assumption A1). Pass ``provider="openai"`` + an
``OPENAI_API_KEY`` env var to use the real model at runtime.

The recommended path for routing LLM calls is the **model connector**
(:mod:`maestro.connectors`): :class:`ConnectorReasoner` wraps any
``ModelConnector`` so the agent can run against OpenAI, Anthropic, Ollama, a
local engine, or a custom provider without code changes — the framework calls
the connector, never a provider SDK directly.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..telemetry.detection import Alert, AlertClass

if TYPE_CHECKING:
    from ..connectors import ChatResponse, ModelConnector


@dataclass
class ReasoningResult:
    summary: str
    severity: float
    action: str
    latency_ms: float = 100.0


# Alert class -> planner action, kept aligned with the Sec 5.3 L3 allow-list so
# an LLM-backed reasoner still yields a valid, validatable action.
_ACTION_FOR_ALERT: dict[AlertClass, str] = {
    AlertClass.DOS: "throttle_telemetry",
    AlertClass.ANOMALY: "raise_thresholds",
}


def _action_for(alert: Alert) -> str:
    return _ACTION_FOR_ALERT.get(alert.cls, "noop")


class StubReasoner:
    """Deterministic stub used by default (assumption A1)."""

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        if alert.cls == AlertClass.DOS:
            return ReasoningResult(
                summary="Telemetry saturated; DoS signature matched. Throttle WS stream.",
                severity=alert.severity,
                action="throttle_telemetry",
                latency_ms=80.0,
            )
        if alert.cls == AlertClass.ANOMALY:
            return ReasoningResult(
                summary="Abnormal telemetry pattern; elevate anomaly threshold.",
                severity=alert.severity,
                action="raise_thresholds",
                latency_ms=70.0,
            )
        return ReasoningResult(
            summary="Baseline conditions; no action required.",
            severity=0.1,
            action="noop",
            latency_ms=40.0,
        )


class ConnectorReasoner:
    """Reasoner backed by a :class:`~maestro.connectors.ModelConnector`.

    Routes the reasoning step through the connector abstraction so the same
    agent code runs against any registered backend (cloud or local). The alert
    is rendered into a domain prompt; the connector's normalized response text
    becomes the summary, while the action is derived deterministically from the
    alert class (keeping it within the Sec 5.3 L3 allow-list regardless of what
    the model returns).
    """

    SYSTEM_PROMPT = (
        "You are an LLM-based network-monitoring agent reasoning over telemetry "
        "alerts (Sec 3.1 LLM Reasoning Engine). Given an alert, respond with a "
        "one-sentence assessment and the recommended mitigation."
    )

    def __init__(self, connector: ModelConnector, *, max_tokens: int = 128):
        self.connector = connector
        self.max_tokens = max_tokens

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        from ..connectors import ChatRequest

        prompt = (
            f"Alert class: {alert.cls.value}\n"
            f"Severity: {alert.severity:.2f}\n"
            f"Detail: {alert.detail}\n"
            "Assess the situation and recommend a mitigation."
        )
        request = ChatRequest.of(
            prompt, system=self.SYSTEM_PROMPT, max_tokens=self.max_tokens
        )
        response: ChatResponse = self.connector.chat(request)
        return ReasoningResult(
            summary=response.text.strip() or f"{alert.cls.value} alert observed.",
            severity=alert.severity,
            action=_action_for(alert),
            latency_ms=response.latency_ms,
        )


def reasoner_from_registry(name: str | None = None, **build_kwargs: object) -> ConnectorReasoner:
    """Build a :class:`ConnectorReasoner` from the connector registry.

    ``name`` selects a registered connector (defaults to the registry default).
    """
    from ..connectors import build_registry

    registry = build_registry(**build_kwargs)  # type: ignore[arg-type]
    return ConnectorReasoner(registry.resolve(name))


def get_reasoner(provider: str = "stub", model: str = "stub-reasoner",
                 api_key_env: str = "OPENAI_API_KEY",
                 connector: ModelConnector | None = None) -> Reasoner:
    """Factory; returns a callable following Sec 3.1 LLM Reasoning Engine spec.

    ``provider="connector"`` wraps the supplied ``connector`` (or the registry
    default) in a :class:`ConnectorReasoner`.
    """
    if provider == "stub":
        return StubReasoner()
    if provider == "connector":
        if connector is not None:
            return ConnectorReasoner(connector)  # type: ignore[return-value]
        return reasoner_from_registry()  # type: ignore[return-value]
    if provider == "openai":
        try:
            from openai import OpenAI
        except ImportError as e:
            raise ImportError(
                "provider='openai' requires `pip install 'maestro-secure-agentic-ai[openai]'`") from e
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise RuntimeError(f"env var {api_key_env} not set")
        client = OpenAI(api_key=api_key)

        class _OpenAIReasoner:
            def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
                t0 = time.time()
                resp = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system",
                         "content": ("You are an LLM-based network monitoring agent reasoning "
                                     "over alerts (Sec 3.1 LLM Reasoning Engine).")},
                        {"role": "user",
                         "content": f"Alert: {alert.cls.value} sev={alert.severity:.2f} {alert.detail}"},
                    ],
                )
                txt = resp.choices[0].message.content or ""
                ms = (time.time() - t0) * 1000.0
                return ReasoningResult(summary=txt, severity=alert.severity,
                                       action="noop", latency_ms=ms)

        return _OpenAIReasoner()  # type: ignore[return-value]
    raise ValueError(f"Unknown provider: {provider}")


Reasoner = StubReasoner  # alias for type-checkers; runtime duck-typed
