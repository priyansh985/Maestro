"""Ollama connector for local model inference.

Wire format: ``POST {base_url}/api/chat`` (default ``http://localhost:11434``),
no authentication. This is the "offline / local model" path in the connector
system — it runs against a locally-served model with no cloud dependency.
"""
from __future__ import annotations

from typing import Any

from ..base import ChatRequest, GenerationResult, Usage
from .http_base import HttpConnector

OLLAMA_BASE_URL = "http://localhost:11434"


class OllamaConnector(HttpConnector):
    """Connector for a local Ollama server."""

    provider = "ollama"

    def __init__(
        self,
        name: str = "ollama",
        model: str = "llama3",
        *,
        base_url: str = OLLAMA_BASE_URL,
        **kw: Any,
    ):
        # Ollama needs no API key.
        super().__init__(name, model, base_url=base_url, api_key=None, **kw)

    def _build_payload(self, request: ChatRequest, model: str) -> dict[str, Any]:
        p = request.params
        options: dict[str, Any] = {"temperature": p.temperature, "num_predict": p.max_tokens}
        if p.top_p is not None:
            options["top_p"] = p.top_p
        if p.stop:
            options["stop"] = p.stop
        return {
            "model": model,
            "messages": [m.to_dict() for m in request.messages],
            "stream": False,
            "options": options,
        }

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        data = self._post_json("/api/chat", self._build_payload(request, model))
        text = (data.get("message") or {}).get("content") or ""
        usage = Usage(
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            completion_tokens=int(data.get("eval_count", 0)),
        )
        return GenerationResult(
            text=text,
            model=str(data.get("model", model)),
            usage=usage,
            finish_reason=data.get("done_reason") or ("stop" if data.get("done") else None),
            raw=data,
        )
