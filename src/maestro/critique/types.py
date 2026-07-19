"""Shared types for the HMDC critique engine (blueprint §5).

The Hybrid Multi-Dimensional Critique scores a candidate output across four
*ordered, gated* stages — it does **not** average them into one number. These
dataclasses carry the inputs (what "good" means) and the layered result (what
each stage found), so the final verdict is explainable rather than a magic score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    PASS = "pass"                      # cleared every stage
    REVISE = "revise"                  # soft issues (drift / low ensemble) → regenerate
    ROUTE_TO_HUMAN = "route_to_human"  # judge disagreement / no independent judge
    REJECT = "reject"                  # a deterministic guardrail hard-failed


@dataclass(frozen=True)
class RubricCriterion:
    """One anchored scoring dimension. ``description`` is the anchor the judge
    scores against (concrete, not "is it good?")."""

    name: str
    description: str
    weight: float = 1.0                # relative weight *within* the rubric only


@dataclass(frozen=True)
class Candidate:
    """A model output under critique. ``family`` names the generating model
    family so the engine can enforce cross-family judging."""

    text: str
    family: str = "unknown"
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CritiqueSpec:
    """What the output should accomplish + the thresholds that gate it."""

    intent: str                                    # what the output must accomplish
    grounding: tuple[str, ...] = ()                # source text the answer must align with
    rubric: tuple[RubricCriterion, ...] = ()
    forbidden_patterns: tuple[str, ...] = ()       # extra deterministic content guardrails
    required_format: str | None = None             # e.g. "json"
    min_semantic_alignment: float = 0.25           # Stage-2 floor (a gate, not a weight)
    min_ensemble_score: float = 0.5                # Stage-4 floor
    route_variance_threshold: float = 0.05         # judge disagreement that routes to a human


@dataclass(frozen=True)
class GuardrailResult:
    passed: bool
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifierResult:
    """Outcome of an *environmental* / task-specific verification (blueprint §5.3).

    This is the deterministic, domain-specific correctness signal — tests pass,
    a ledger reconciles, a claim is source-supported, a motion is within the
    safety envelope. It is the strongest signal in the pipeline and, unlike a
    judge, it is a fact, not an opinion.
    """

    verified: bool
    signal: str                 # what was checked, e.g. "test-suite", "reconciliation"
    reason: str = ""


@dataclass(frozen=True)
class JudgeScore:
    judge_family: str
    per_criterion: dict[str, float]                # 0..1 per rubric criterion
    overall: float                                 # length-normalized aggregate 0..1
    notes: str = ""


@dataclass(frozen=True)
class CritiqueResult:
    """The layered outcome — each stage's finding is preserved, not collapsed."""

    verdict: Verdict
    reason: str
    guardrails: GuardrailResult
    semantic_alignment: float
    judge_scores: tuple[JudgeScore, ...]
    ensemble_mean: float
    ensemble_variance: float
    excluded_same_family: tuple[str, ...] = ()
    task_verified: bool | None = None       # environmental verification (None = not run)

    @property
    def passed(self) -> bool:
        return self.verdict is Verdict.PASS

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "guardrails": {"passed": self.guardrails.passed,
                           "failures": list(self.guardrails.failures)},
            "semantic_alignment": round(self.semantic_alignment, 4),
            "judge_scores": [
                {"judge_family": s.judge_family, "overall": round(s.overall, 4),
                 "per_criterion": {k: round(v, 4) for k, v in s.per_criterion.items()},
                 "notes": s.notes}
                for s in self.judge_scores
            ],
            "ensemble_mean": round(self.ensemble_mean, 4),
            "ensemble_variance": round(self.ensemble_variance, 4),
            "excluded_same_family": list(self.excluded_same_family),
            "task_verified": self.task_verified,
        }
