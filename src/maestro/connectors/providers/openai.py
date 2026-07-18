"""OpenAI Chat Completions connector (also the base for custom OpenAI-compatible
providers such as vLLM, LM Studio, Together, Groq, OpenRouter, …).

Wire format: ``POST {base_url}/chat/completions`` with a Bearer token.
"""
from __future__ import annotations

from typing import Any

from ..base import ChatRequest, GenerationResult, Usage
from .http_base import HttpConnector

OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIConnector(HttpConnector):
    """Connector for the OpenAI Chat Completions API."""

    provider = "openai"

    def __init__(
        self,
        name: str = "openai",
        model: str = "gpt-4o-mini",
        *,
        base_url: str = OPENAI_BASE_URL,
        api_key: str | None = None,
        **kw: Any,
    ):
        super().__init__(name, model, base_url=base_url, api_key=api_key, **kw)

    def _build_payload(self, request: ChatRequest, model: str) -> dict[str, Any]:
        p = request.params
        payload: dict[str, Any] = {
            "model": model,
            "messages": [m.to_dict() for m in request.messages],
            "max_tokens": p.max_tokens,
            "temperature": p.temperature,
        }
        if p.top_p is not None:
            payload["top_p"] = p.top_p
        if p.stop:
            payload["stop"] = p.stop
        payload.update(p.extra)
        return payload

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        data = self._post_json("/chat/completions", self._build_payload(request, model))
        choice = (data.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content") or ""
        usage_raw = data.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_raw.get("prompt_tokens", 0)),
            completion_tokens=int(usage_raw.get("completion_tokens", 0)),
        )
        return GenerationResult(
            text=text,
            model=str(data.get("model", model)),
            usage=usage,
            finish_reason=choice.get("finish_reason"),
            raw=data,
        )
