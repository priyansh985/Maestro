"""Deterministic offline connector.

The stub never touches the network. It echoes a summary of the request so the
whole system — dashboard, fallback, agent integration, tests — can run offline
and produce stable, assertable output with no API key.
"""
from __future__ import annotations

from ..base import ChatRequest, GenerationResult, ModelConnector, Role, Usage, role_str


class StubConnector(ModelConnector):
    """A no-network connector with deterministic responses."""

    provider = "stub"

    def __init__(self, name: str = "stub", model: str = "stub-1", *, enabled: bool = True,
                 prefix: str = "[stub]"):
        super().__init__(name, model, enabled=enabled)
        self.prefix = prefix

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        last_user = next(
            (m.content for m in reversed(request.messages)
             if role_str(m.role) == Role.USER.value),
            "",
        )
        system = request.system_prompt()
        parts = [f"{self.prefix} model={model}"]
        if system:
            parts.append(f"system={system[:80]!r}")
        parts.append(f"reply to: {last_user[:200]}")
        text = " | ".join(parts)
        # Deterministic, measured-style usage so tests can assert on it.
        usage = Usage(
            prompt_tokens=sum(len(m.content.split()) for m in request.messages),
            completion_tokens=len(text.split()),
        )
        return GenerationResult(
            text=text,
            model=model,
            usage=usage,
            finish_reason="stop",
            raw={"stub": True},
        )
