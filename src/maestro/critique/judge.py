"""Stage 3 — LLM-as-a-Judge with structured rubrics (cross-family).

**Honest scope.** :class:`RubricJudge` is a *deterministic, offline* stand-in
for a real cross-family LLM judge (which a production HMDC drives through the
connector layer). What matters is the *contract the engine enforces around* the
judge, which holds for any implementation:

* it scores **each anchored rubric criterion**, not one vague "goodness" scalar;
* it **length-normalizes** — a verbose answer padded with off-topic filler is
  down-weighted (verbosity bias), via information density;
* it carries a ``family`` tag so the engine can require a judge from a
  **different family than the generator** (self-preference bias).

A judge is *evidence*, never the verdict — the engine (Stage 4) decides, and a
low or disputed judge signal routes to a human rather than being trusted.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .embedding import Embedder, LexicalEmbedder, cosine, information_density
from .types import Candidate, CritiqueSpec, JudgeScore


@runtime_checkable
class Judge(Protocol):
    family: str

    def score(self, candidate: Candidate, spec: CritiqueSpec) -> JudgeScore:
        ...


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


class RubricJudge:
    """A deterministic rubric judge with verbosity-bias normalization."""

    def __init__(self, family: str, *, embedder: Embedder | None = None) -> None:
        if not family:
            raise ValueError("a judge must declare a model family (for cross-family checks)")
        self.family = family
        self._embedder = embedder if embedder is not None else LexicalEmbedder()

    def score(self, candidate: Candidate, spec: CritiqueSpec) -> JudgeScore:
        cand_vec = self._embedder.embed(candidate.text)
        grounding = " ".join(spec.grounding)

        per_criterion: dict[str, float] = {}
        weights: dict[str, float] = {}
        if spec.rubric:
            for crit in spec.rubric:
                anchor = f"{crit.description} {spec.intent} {grounding}"
                per_criterion[crit.name] = cosine(cand_vec, self._embedder.embed(anchor))
                weights[crit.name] = crit.weight
        else:
            per_criterion["intent-alignment"] = cosine(
                cand_vec, self._embedder.embed(f"{spec.intent} {grounding}"))
            weights["intent-alignment"] = 1.0

        total_w = sum(weights.values()) or 1.0
        raw = sum(per_criterion[k] * weights[k] for k in per_criterion) / total_w

        # Verbosity bias: down-weight answers padded with off-topic tokens.
        reference_vocab = set()
        for piece in (spec.intent, grounding, *(c.description for c in spec.rubric)):
            reference_vocab |= set(self._embedder.embed(piece))
        density = information_density(candidate.text, reference_vocab)
        verbosity_factor = 0.5 + 0.5 * density
        overall = _clamp01(raw * verbosity_factor)

        return JudgeScore(
            judge_family=self.family,
            per_criterion=per_criterion,
            overall=overall,
            notes=f"raw={raw:.3f} density={density:.3f}",
        )
