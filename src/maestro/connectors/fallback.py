"""Fallback connector — graceful degradation across an ordered chain.

Wraps an ordered list of connectors and tries them in turn. On a *retryable*
failure (rate limit, provider unavailable) or a disabled connector, it moves to
the next candidate — e.g. cloud API first, local Ollama/stub as the safety net.
Non-retryable failures (bad request, auth) are raised immediately, since
retrying a different backend won't help a malformed request.
"""
from __future__ import annotations

from collections.abc import Callable

from .base import (
    ChatRequest,
    ChatResponse,
    ConnectorError,
    GenerationResult,
    ModelConnector,
    ProviderUnavailableError,
)

FallbackHook = Callable[[ModelConnector, ConnectorError], None]


class FallbackConnector(ModelConnector):
    """Try each connector in order until one succeeds."""

    provider = "fallback"

    def __init__(
        self,
        name: str,
        connectors: list[ModelConnector],
        *,
        enabled: bool = True,
        on_fallback: FallbackHook | None = None,
    ):
        if not connectors:
            raise ValueError("FallbackConnector requires at least one connector")
        # ``model`` mirrors the primary connector's model for describe().
        super().__init__(name, connectors[0].model, enabled=enabled)
        self.connectors = connectors
        self.on_fallback = on_fallback

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:  # pragma: no cover
        # Not used: ``chat`` is overridden so each delegate does its own timing.
        raise NotImplementedError

    def chat(self, request: ChatRequest) -> ChatResponse:
        if not self.enabled:
            raise ProviderUnavailableError(
                f"connector '{self.name}' is disabled", provider=self.provider
            )
        last_error: ConnectorError | None = None
        for connector in self.connectors:
            if not connector.enabled:
                continue
            try:
                return connector.chat(request)
            except ConnectorError as exc:
                last_error = exc
                if not exc.retryable:
                    raise  # bad request / auth: another backend won't fix it
                if self.on_fallback is not None:
                    self.on_fallback(connector, exc)
        raise last_error or ProviderUnavailableError(
            f"no enabled connectors in fallback '{self.name}'", provider=self.provider
        )

    def describe(self) -> dict[str, object]:
        d = super().describe()
        d["chain"] = [c.name for c in self.connectors]
        return d
