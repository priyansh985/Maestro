"""Provider-agnostic model-connector abstraction.

This module defines the single, normalized surface every LLM provider is
adapted to: a :class:`ModelConnector` exposes one ``chat()`` method that takes
a :class:`ChatRequest` and returns a :class:`ChatResponse` with normalized
usage and latency metrics, regardless of whether the backend is OpenAI,
Anthropic, Ollama, a local engine, or a custom OpenAI-compatible endpoint.

Design notes
------------
* Concrete HTTP connectors receive an injectable ``httpx.Client`` so they can
  be exercised **offline and deterministically** in tests via
  ``httpx.MockTransport`` — no network and no API keys required.
* ``chat()`` is the only method callers use. It times the request, wraps
  provider errors into the :class:`ConnectorError` hierarchy, and fills in a
  best-effort token estimate when a provider does not report usage, so every
  response carries latency + token metrics for the testing dashboard.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class ConnectorError(Exception):
    """Base class for all connector failures.

    ``provider`` and ``status_code`` are populated when known so callers (and
    the fallback logic) can branch on the failure class without string
    matching.
    """

    retryable: bool = False

    def __init__(self, message: str, *, provider: str = "", status_code: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class AuthenticationError(ConnectorError):
    """Missing/invalid credentials (HTTP 401/403)."""


class InvalidRequestError(ConnectorError):
    """Malformed request rejected by the provider (HTTP 4xx)."""


class RateLimitError(ConnectorError):
    """Provider throttled the request (HTTP 429). Retryable/fallback-eligible."""

    retryable = True


class ProviderUnavailableError(ConnectorError):
    """Provider is unreachable or returned 5xx. Retryable/fallback-eligible."""

    retryable = True


# --------------------------------------------------------------------------- #
# Message / request / response value objects
# --------------------------------------------------------------------------- #
class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


def role_str(role: Role | str) -> str:
    return role.value if isinstance(role, Role) else str(role)


@dataclass
class ChatMessage:
    """A single conversation message in the normalized format."""

    role: Role | str
    content: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": role_str(self.role), "content": self.content}
        if self.name:
            d["name"] = self.name
        return d


@dataclass
class ChatParams:
    """Generation parameters common across providers.

    Only ``max_tokens`` is universally forwarded. ``temperature`` / ``top_p``
    are forwarded where the provider/model accepts them (some newer models
    reject sampling params — see the Anthropic connector). ``extra`` carries
    provider-specific passthrough options.
    """

    temperature: float = 0.7
    max_tokens: int = 512
    top_p: float | None = None
    stop: list[str] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChatRequest:
    """A normalized chat-completion request."""

    messages: list[ChatMessage]
    params: ChatParams = field(default_factory=ChatParams)
    model: str | None = None  # overrides the connector's default model

    def system_prompt(self) -> str:
        """Concatenated text of all ``system`` messages (providers that take a
        dedicated system field, e.g. Anthropic, need this split out)."""
        return "\n\n".join(
            m.content for m in self.messages if role_str(m.role) == Role.SYSTEM.value
        )

    def non_system_messages(self) -> list[ChatMessage]:
        return [m for m in self.messages if role_str(m.role) != Role.SYSTEM.value]

    @classmethod
    def of(cls, prompt: str, *, system: str = "", **params: Any) -> ChatRequest:
        """Convenience builder for the common ``(system?, prompt)`` case."""
        msgs: list[ChatMessage] = []
        if system:
            msgs.append(ChatMessage(Role.SYSTEM, system))
        msgs.append(ChatMessage(Role.USER, prompt))
        return cls(messages=msgs, params=ChatParams(**params))


@dataclass
class Usage:
    """Token accounting for one request."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated: bool = False  # True when derived from the heuristic estimator

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated": self.estimated,
        }


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) for providers that omit usage.

    Deliberately provider-neutral and dependency-free; flagged via
    ``Usage.estimated`` so the dashboard can distinguish measured from
    estimated counts.
    """
    if not text:
        return 0
    return max(1, round(len(text) / 4))


@dataclass
class GenerationResult:
    """Low-level result a concrete connector returns from ``_generate``.

    The base class turns this into a :class:`ChatResponse`, adding latency and
    filling in estimated usage when ``usage`` is ``None``.
    """

    text: str
    model: str
    usage: Usage | None = None
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChatResponse:
    """Normalized response returned to every caller."""

    text: str
    model: str
    provider: str
    connector: str
    usage: Usage
    latency_ms: float
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "model": self.model,
            "provider": self.provider,
            "connector": self.connector,
            "usage": self.usage.to_dict(),
            "latency_ms": round(self.latency_ms, 2),
            "finish_reason": self.finish_reason,
        }


# --------------------------------------------------------------------------- #
# Connector base class
# --------------------------------------------------------------------------- #
class ModelConnector(abc.ABC):
    """Base class for all connectors.

    Subclasses implement :meth:`_generate`; everything else (timing, error
    normalization, usage estimation, enable/disable) is handled here so every
    backend presents an identical ``chat()`` surface.
    """

    #: Stable provider identifier, e.g. ``"openai"`` / ``"anthropic"``.
    provider: str = "base"

    def __init__(self, name: str, model: str, *, enabled: bool = True):
        self.name = name
        self.model = model
        self.enabled = enabled

    # -- subclass hook ----------------------------------------------------- #
    @abc.abstractmethod
    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        """Perform one provider call. Raise a :class:`ConnectorError` subclass
        on failure. ``model`` is the already-resolved model id."""

    def health_check(self) -> bool:  # pragma: no cover - trivial default
        """Cheap liveness probe. Subclasses may override with a real ping.

        The default sends a 1-token prompt through ``chat()`` and reports
        whether it succeeded.
        """
        try:
            self.chat(ChatRequest.of("ping", max_tokens=1))
            return True
        except ConnectorError:
            return False

    # -- public surface ---------------------------------------------------- #
    def chat(self, request: ChatRequest) -> ChatResponse:
        """Run a chat completion and return a normalized response."""
        if not self.enabled:
            raise ProviderUnavailableError(
                f"connector '{self.name}' is disabled", provider=self.provider
            )
        model = request.model or self.model
        start = time.perf_counter()
        try:
            result = self._generate(request, model)
        except ConnectorError:
            raise
        except Exception as exc:  # normalize anything unexpected
            raise ConnectorError(
                f"{self.provider} connector error: {exc}", provider=self.provider
            ) from exc
        latency_ms = (time.perf_counter() - start) * 1000.0

        # Fill in any token count the provider omitted (estimated per-field so a
        # provider that reports only completion tokens still gets a prompt
        # estimate, rather than under-reporting input as zero).
        usage = result.usage or Usage()
        if usage.prompt_tokens == 0:
            prompt_text = "\n".join(m.content for m in request.messages)
            if prompt_text:
                usage.prompt_tokens = estimate_tokens(prompt_text)
                usage.estimated = True
        if usage.completion_tokens == 0 and result.text:
            usage.completion_tokens = estimate_tokens(result.text)
            usage.estimated = True
        return ChatResponse(
            text=result.text,
            model=result.model or model,
            provider=self.provider,
            connector=self.name,
            usage=usage,
            latency_ms=latency_ms,
            finish_reason=result.finish_reason,
            raw=result.raw,
        )

    def describe(self) -> dict[str, Any]:
        """Metadata for the dashboard / API (never leaks secrets)."""
        return {
            "name": self.name,
            "provider": self.provider,
            "model": self.model,
            "enabled": self.enabled,
        }
