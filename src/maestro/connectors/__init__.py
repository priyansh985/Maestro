"""Maestro model-connector system.

A provider-agnostic abstraction over LLM backends (OpenAI, Anthropic, Ollama,
local engines, and custom external providers) with a single ``chat()`` surface,
graceful fallback, and a name-keyed registry. See ``docs/CONNECTORS.md``.
"""
from __future__ import annotations

from .base import (
    AuthenticationError,
    ChatMessage,
    ChatParams,
    ChatRequest,
    ChatResponse,
    ConnectorError,
    GenerationResult,
    InvalidRequestError,
    ModelConnector,
    ProviderUnavailableError,
    RateLimitError,
    Role,
    Usage,
    estimate_tokens,
)
from .config import build_registry, default_registry
from .fallback import FallbackConnector
from .providers import (
    AnthropicConnector,
    CustomConnector,
    OllamaConnector,
    OpenAIConnector,
    StubConnector,
)
from .registry import PROVIDER_CLASSES, ConnectorRegistry

__all__ = [
    # base
    "ModelConnector",
    "ChatMessage",
    "ChatParams",
    "ChatRequest",
    "ChatResponse",
    "GenerationResult",
    "Usage",
    "Role",
    "estimate_tokens",
    # errors
    "ConnectorError",
    "AuthenticationError",
    "InvalidRequestError",
    "RateLimitError",
    "ProviderUnavailableError",
    # providers
    "StubConnector",
    "OpenAIConnector",
    "AnthropicConnector",
    "OllamaConnector",
    "CustomConnector",
    # composition
    "FallbackConnector",
    "ConnectorRegistry",
    "PROVIDER_CLASSES",
    "build_registry",
    "default_registry",
]
