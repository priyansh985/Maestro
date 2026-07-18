"""Connector registry — register / enable / disable / resolve connectors.

The registry is the single place the framework and the web dashboard use to
look up a connector by name, so LLM calls are never hardwired to a provider.
Registering an external provider is a data operation (URL + key + provider
kind), not a code change.
"""
from __future__ import annotations

import contextlib

import httpx

from .base import ModelConnector
from .providers.anthropic import AnthropicConnector
from .providers.custom import CustomConnector
from .providers.ollama import OllamaConnector
from .providers.openai import OpenAIConnector
from .providers.stub import StubConnector

#: Provider-kind -> connector class, used by :meth:`register_provider`.
PROVIDER_CLASSES: dict[str, type[ModelConnector]] = {
    "stub": StubConnector,
    "openai": OpenAIConnector,
    "anthropic": AnthropicConnector,
    "ollama": OllamaConnector,
    "custom": CustomConnector,
}


class ConnectorRegistry:
    """An ordered, name-keyed collection of connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, ModelConnector] = {}
        self._default: str | None = None

    # -- registration ------------------------------------------------------ #
    def register(self, connector: ModelConnector, *, default: bool = False) -> ModelConnector:
        if connector.name in self._connectors:
            raise ValueError(f"connector '{connector.name}' already registered")
        self._connectors[connector.name] = connector
        # Auto-select a default only from an *enabled* connector, so resolve()
        # never returns a disabled one just because it registered first. An
        # explicit default=True still wins regardless of enabled state.
        if default or (self._default is None and connector.enabled):
            self._default = connector.name
        return connector

    def register_provider(
        self,
        *,
        name: str,
        provider: str,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        default: bool = False,
        http_client: httpx.Client | None = None,
        **extra: object,
    ) -> ModelConnector:
        """Build and register a connector from plain config (the API/dashboard
        path for adding an external provider)."""
        cls = PROVIDER_CLASSES.get(provider)
        if cls is None:
            raise ValueError(
                f"unknown provider '{provider}'; known: {sorted(PROVIDER_CLASSES)}"
            )
        kwargs: dict[str, object] = {"name": name, "model": model}
        if base_url is not None:
            kwargs["base_url"] = base_url
        if api_key is not None:
            kwargs["api_key"] = api_key
        # HTTP-backed connectors accept an injectable client; the stub does not.
        if provider != "stub" and http_client is not None:
            kwargs["http_client"] = http_client
        kwargs.update(extra)
        return self.register(cls(**kwargs), default=default)  # type: ignore[arg-type]

    def remove(self, name: str) -> None:
        connector = self._connectors.pop(name, None)
        # Release any connector-owned HTTP client (avoids leaking the
        # connection pool for the process lifetime on register/remove cycles).
        close = getattr(connector, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()
        if self._default == name:
            self._default = next(iter(self._connectors), None)

    def close_all(self) -> None:
        """Close every connector that owns an HTTP client."""
        for connector in self._connectors.values():
            close = getattr(connector, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):
                    close()

    # -- enable / disable -------------------------------------------------- #
    def set_enabled(self, name: str, enabled: bool) -> ModelConnector:
        connector = self.get(name)
        connector.enabled = enabled
        return connector

    def enable(self, name: str) -> ModelConnector:
        return self.set_enabled(name, True)

    def disable(self, name: str) -> ModelConnector:
        return self.set_enabled(name, False)

    # -- lookup ------------------------------------------------------------ #
    def get(self, name: str) -> ModelConnector:
        try:
            return self._connectors[name]
        except KeyError as exc:
            raise KeyError(f"no connector named '{name}'") from exc

    def resolve(self, name: str | None = None) -> ModelConnector:
        """Return ``name`` or the default connector."""
        if name:
            return self.get(name)
        if self._default is None:
            raise KeyError("registry is empty; no default connector")
        return self.get(self._default)

    @property
    def default_name(self) -> str | None:
        return self._default

    def set_default(self, name: str) -> None:
        if name not in self._connectors:
            raise KeyError(f"no connector named '{name}'")
        self._default = name

    def names(self) -> list[str]:
        return list(self._connectors)

    def list_descriptions(self) -> list[dict[str, object]]:
        out = []
        for name, connector in self._connectors.items():
            d = connector.describe()
            d["default"] = name == self._default
            out.append(d)
        return out
