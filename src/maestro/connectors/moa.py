"""Mixture of Agents (MoA) — response aggregation for high-stakes queries (§6).

MoA runs several proposer models in parallel and synthesizes a consensus. Its
real value for a *security* control plane is not just quality: the **spread of
the proposals is an uncertainty signal**. High disagreement on a consequential
query should route to a human, not be averaged into false confidence.

⚑ Use MoA as a *targeted escalation*, never the default path — it multiplies
cost and latency by ``N (+1)``. :func:`moa_recommended` gates it on the risk
band / confidence so the tax is paid only where it buys something.

The aggregation is offline and deterministic: with no aggregator connector the
**medoid** (the proposal most representative of the set) is returned; supply an
aggregator connector to synthesize instead.
"""
from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

from .base import ChatRequest, ChatResponse, ModelConnector

#: Decision bands (from the residual-risk engine) that warrant MoA escalation.
_HIGH_STAKES_BANDS = frozenset(
    {"require_approval", "deny_autonomous", "emergency_containment"})


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _similarity(a: str, b: str) -> float:
    """Token-set cosine similarity of two texts, in ``[0, 1]``."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / math.sqrt(len(ta) * len(tb))


def moa_recommended(
    decision: str = "", *, confidence: float | None = None, confidence_floor: float = 0.5
) -> bool:
    """True if a query is worth the MoA tax (high-stakes band or low confidence)."""
    if decision in _HIGH_STAKES_BANDS:
        return True
    return confidence is not None and confidence < confidence_floor


@dataclass(frozen=True)
class MoAResult:
    """The synthesized response plus the disagreement signal."""

    response: ChatResponse
    proposer_texts: tuple[str, ...]
    disagreement: float           # 0 (consensus) .. 1 (total divergence)
    route_to_human: bool

    @property
    def proposer_count(self) -> int:
        return len(self.proposer_texts)


class MixtureOfAgents:
    """Aggregate N proposer connectors, surfacing disagreement as uncertainty."""

    def __init__(
        self,
        proposers: Sequence[ModelConnector],
        *,
        aggregator: ModelConnector | None = None,
        disagreement_threshold: float = 0.5,
        name: str = "moa",
    ) -> None:
        if len(proposers) < 2:
            raise ValueError("MoA needs at least 2 proposers to be meaningful")
        self._proposers = tuple(proposers)
        self._aggregator = aggregator
        self._threshold = disagreement_threshold
        self.name = name

    @property
    def cost_multiplier(self) -> int:
        """Calls per request relative to a single model (the cost/latency tax)."""
        return len(self._proposers) + (1 if self._aggregator is not None else 0)

    def chat(self, request: ChatRequest) -> MoAResult:
        responses = [p.chat(request) for p in self._proposers]
        texts = tuple(r.text for r in responses)
        disagreement = self._disagreement(texts)
        aggregate = self._aggregate(texts, responses)
        return MoAResult(
            response=aggregate,
            proposer_texts=texts,
            disagreement=disagreement,
            route_to_human=disagreement > self._threshold,
        )

    def _disagreement(self, texts: tuple[str, ...]) -> float:
        pairs = [
            _similarity(texts[i], texts[j])
            for i in range(len(texts)) for j in range(i + 1, len(texts))
        ]
        mean_sim = sum(pairs) / len(pairs) if pairs else 1.0
        return round(1.0 - mean_sim, 4)

    def _aggregate(
        self, texts: tuple[str, ...], responses: list[ChatResponse]
    ) -> ChatResponse:
        if self._aggregator is not None:
            proposals = "\n".join(f"- {t}" for t in texts)
            prompt = ("Synthesize a single best answer from these candidate "
                      f"proposals:\n{proposals}")
            return self._aggregator.chat(ChatRequest.of(prompt))
        # Medoid: the proposal most representative of the set (deterministic).
        best_index, best_score = 0, -1.0
        for i in range(len(texts)):
            score = sum(_similarity(texts[i], texts[j])
                        for j in range(len(texts)) if j != i)
            if score > best_score:
                best_index, best_score = i, score
        return responses[best_index]
