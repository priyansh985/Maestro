"""LLM Reasoning Engine (Sec 3.1 L1 + control loop).

The paper uses ``pydantic-ai`` + an LLM (Sec 6.1) with domain prompts (Sec
6.1). To keep the reproduction offline + deterministic we ship a
``stub`` provider (assumption A1). Pass ``provider="openai"`` + an
``OPENAI_API_KEY`` env var to use the real model at runtime.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Literal, Optional

from ..telemetry.detection import Alert, AlertClass


@dataclass
class ReasoningResult:
    summary: str
    severity: float
    action: str
    latency_ms: float = 100.0


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


def get_reasoner(provider: str = "stub", model: str = "stub-reasoner",
                 api_key_env: str = "OPENAI_API_KEY") -> "Reasoner":
    """Factory; returns a callable following Sec 3.1 LLM Reasoning Engine spec."""
    if provider == "stub":
        return StubReasoner()
    if provider == "openai":
        try:
            from openai import OpenAI  # type: ignore
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
                resp = client.chat.completions.create(  # type: ignore[attr-defined]
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
