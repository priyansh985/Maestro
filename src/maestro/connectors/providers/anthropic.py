"""Anthropic Messages API connector.

Wire format: ``POST {base_url}/v1/messages`` with the ``x-api-key`` and
``anthropic-version`` headers. The ``system`` prompt is a top-level field
(Anthropic does not accept a ``system`` role inside ``messages``), and the
response text lives in ``content[]`` blocks of type ``text``.

Note on sampling params: newer Claude models (e.g. ``claude-opus-4-8``) reject
``temperature``/``top_p`` with a 400, so this connector does **not** forward
them by default. Set ``params.extra["temperature"]`` explicitly to opt in when
targeting an older model that accepts it.
"""
from __future__ import annotations

from typing import Any

from ..base import ChatRequest, GenerationResult, Usage
from .http_base import HttpConnector

ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicConnector(HttpConnector):
    """Connector for the Anthropic Messages API."""

    provider = "anthropic"

    def __init__(
        self,
        name: str = "anthropic",
        model: str = DEFAULT_MODEL,
        *,
        base_url: str = ANTHROPIC_BASE_URL,
        api_key: str | None = None,
        anthropic_version: str = ANTHROPIC_VERSION,
        forward_sampling: bool = False,
        **kw: Any,
    ):
        super().__init__(name, model, base_url=base_url, api_key=api_key, **kw)
        self.anthropic_version = anthropic_version
        # Newer Claude models reject temperature/top_p with a 400, so sampling
        # params are dropped by default. Set forward_sampling=True when
        # targeting an older model that accepts them (avoids the silent-drop
        # footgun where a dashboard temperature setting has no effect).
        self.forward_sampling = forward_sampling

    def _headers(self) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
            "anthropic-version": self.anthropic_version,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def _build_payload(self, request: ChatRequest, model: str) -> dict[str, Any]:
        p = request.params
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": p.max_tokens,
            "messages": [m.to_dict() for m in request.non_system_messages()],
        }
        system = request.system_prompt()
        if system:
            payload["system"] = system
        if p.stop:
            payload["stop_sequences"] = p.stop
        # Sampling params are opt-in only (see __init__ / module docstring).
        if self.forward_sampling:
            payload["temperature"] = p.temperature
            if p.top_p is not None:
                payload["top_p"] = p.top_p
        payload.update(p.extra)
        return payload

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        data = self._post_json("/v1/messages", self._build_payload(request, model))
        blocks = data.get("content") or []
        text = "".join(
            b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
        )
        usage_raw = data.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_raw.get("input_tokens", 0)),
            completion_tokens=int(usage_raw.get("output_tokens", 0)),
        )
        return GenerationResult(
            text=text,
            model=str(data.get("model", model)),
            usage=usage,
            finish_reason=data.get("stop_reason"),
            raw=data,
        )
