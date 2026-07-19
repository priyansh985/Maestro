"""The HMDC engine — four ordered, gated stages (blueprint §5).

⚑ The corrections that define this engine (vs. the naive spec):

* **It gates; it does not average.** There is no fixed ``0.2·semantic +
  0.8·judge`` weighting — that would hand authority to the least trustworthy
  component. Instead each stage can *stop* the pipeline:
  1. **Deterministic guardrails** are *dispositive* — a failure is a hard
     ``REJECT`` regardless of anything downstream.
  2. **Semantic alignment** is a *floor* (a gate), not a weighted term: below it,
     the answer is ``REVISE`` and the judges never get to "make up for" drift.
  3. **Cross-family judges only** — a judge from the generator's own family is
     excluded (self-preference bias); if none remain, ``ROUTE_TO_HUMAN``.
  4. **Ensemble is variance-aware** — high inter-judge disagreement
     ``ROUTE_TO_HUMAN`` (disagreement is signal, not noise to average away); a
     low mean is ``REVISE``; otherwise ``PASS``.
* **The judge is evidence, never the verdict.** Its score informs the decision
  and, above all, routes uncertainty to a human.
* **Bias is countered actively** — verbosity (length-normalized in the judge)
  and position (``compare_pairwise`` evaluates both orders and calls a
  order-dependent result a tie, not a winner).

The offline judge/embedder are deterministic stand-ins; the *engine's* contract
holds for any real connector-backed cross-family judge plugged in behind them.
"""
from __future__ import annotations

import statistics
from collections.abc import Callable, Sequence

from .embedding import Embedder, LexicalEmbedder, cosine
from .guardrails import DEFAULT_FORBIDDEN_PATTERNS, deterministic_guardrails
from .judge import Judge
from .types import (
    Candidate,
    CritiqueResult,
    CritiqueSpec,
    Verdict,
    VerifierResult,
)


class HMDCEngine:
    """Runs a candidate through the four gated stages and returns a layered result."""

    def __init__(
        self,
        judges: Sequence[Judge],
        *,
        embedder: Embedder | None = None,
        forbidden: tuple[str, ...] = DEFAULT_FORBIDDEN_PATTERNS,
        task_gate: Callable[[Candidate, dict[str, object]], VerifierResult] | None = None,
    ) -> None:
        if not judges:
            raise ValueError("HMDC needs at least one judge")
        self._judges = tuple(judges)
        self._embedder = embedder if embedder is not None else LexicalEmbedder()
        self._forbidden = forbidden
        self._task_gate = task_gate

    def critique(
        self,
        candidate: Candidate,
        spec: CritiqueSpec,
        *,
        context: dict[str, object] | None = None,
    ) -> CritiqueResult:
        # -- Stage 1: deterministic guardrails (DISPOSITIVE) ----------------- #
        guard = deterministic_guardrails(candidate, spec, extra_forbidden=self._forbidden)
        if not guard.passed:
            return CritiqueResult(
                Verdict.REJECT,
                f"deterministic guardrail failed: {', '.join(guard.failures)}",
                guard, 0.0, (), 0.0, 0.0)

        # -- Stage 2: semantic intent alignment (a FLOOR, not a weight) ------ #
        reference = " ".join((spec.intent, *spec.grounding))
        alignment = cosine(self._embedder.embed(candidate.text), self._embedder.embed(reference))
        if alignment < spec.min_semantic_alignment:
            return CritiqueResult(
                Verdict.REVISE,
                f"semantic alignment {alignment:.2f} below floor {spec.min_semantic_alignment:.2f}",
                guard, alignment, (), 0.0, 0.0)

        # -- Stage 2.5: environmental / task-specific verification ----------- #
        # The strongest correctness signal (blueprint §5.3): a deterministic,
        # domain-specific verifier (tests pass, ledger reconciles, claims are
        # source-supported, motion is within the safety envelope). A failure is
        # an incorrectness/unsafety fact the probabilistic judges cannot override,
        # so it short-circuits before they run.
        task_verified: bool | None = None
        if self._task_gate is not None:
            verification = self._task_gate(candidate, context or {})
            task_verified = verification.verified
            if not verification.verified:
                return CritiqueResult(
                    Verdict.REVISE,
                    f"task verification failed [{verification.signal}]: {verification.reason}",
                    guard, alignment, (), 0.0, 0.0, task_verified=False)

        # -- Stage 3: cross-family judges only (self-preference bias) -------- #
        eligible = [j for j in self._judges if j.family != candidate.family]
        excluded = tuple(sorted({j.family for j in self._judges if j.family == candidate.family}))
        if not eligible:
            return CritiqueResult(
                Verdict.ROUTE_TO_HUMAN,
                "no cross-family judge available (self-preference risk)",
                guard, alignment, (), 0.0, 0.0, excluded, task_verified)
        scores = tuple(j.score(candidate, spec) for j in eligible)

        # -- Stage 4: ensemble — variance-aware, NOT fixed-weight ------------ #
        overalls = [s.overall for s in scores]
        mean = statistics.fmean(overalls)
        variance = statistics.pvariance(overalls) if len(overalls) > 1 else 0.0

        if variance > spec.route_variance_threshold:
            verdict, reason = (
                Verdict.ROUTE_TO_HUMAN,
                f"judge disagreement (variance {variance:.3f}) exceeds "
                f"{spec.route_variance_threshold:.3f}")
        elif mean < spec.min_ensemble_score:
            verdict, reason = (
                Verdict.REVISE,
                f"ensemble score {mean:.2f} below floor {spec.min_ensemble_score:.2f}")
        else:
            verdict, reason = Verdict.PASS, "cleared all stages"

        return CritiqueResult(
            verdict, reason, guard, alignment, scores, mean, variance, excluded, task_verified)


def compare_pairwise(
    a_text: str,
    b_text: str,
    prefer: Callable[[str, str], str],
) -> str:
    """Position-bias-resistant pairwise comparison.

    ``prefer(first, second)`` returns ``"first"`` or ``"second"``. This calls it
    in *both* orders; a genuine preference is order-independent and yields a
    winner (``"a"``/``"b"``), while an order-dependent result (a positional bias)
    is reported as a ``"tie"`` rather than letting presentation order decide.
    """
    r1 = prefer(a_text, b_text)          # a presented first
    r2 = prefer(b_text, a_text)          # b presented first
    winner_1 = a_text if r1 == "first" else b_text
    winner_2 = b_text if r2 == "first" else a_text
    if winner_1 != winner_2:
        return "tie"                     # order changed the answer → position bias
    return "a" if winner_1 == a_text else "b"


__all__ = ["HMDCEngine", "compare_pairwise"]
