"""Hybrid Multi-Dimensional Critique (HMDC) — blueprint §5.

A four-stage, **gated** evaluation of a candidate model output — deterministic
guardrails (dispositive) → semantic alignment (a floor) → cross-family judges →
variance-aware ensemble. It does *not* average the stages into one score, does
*not* let a probabilistic judge override a deterministic gate, and routes
disagreement/uncertainty to a human. Verbosity bias is countered by
length-normalization in the judge; position bias by :func:`compare_pairwise`.

The offline judge/embedder are deterministic stand-ins so the whole pipeline is
testable without a model; the engine's contract holds for a real
connector-backed cross-family LLM judge plugged in behind the same interfaces.
"""
from __future__ import annotations

from .embedding import Embedder, LexicalEmbedder, cosine, information_density
from .engine import HMDCEngine, compare_pairwise
from .guardrails import DEFAULT_FORBIDDEN_PATTERNS, deterministic_guardrails
from .judge import Judge, RubricJudge
from .types import (
    Candidate,
    CritiqueResult,
    CritiqueSpec,
    GuardrailResult,
    JudgeScore,
    RubricCriterion,
    Verdict,
    VerifierResult,
)

__all__ = [
    "Candidate",
    "CritiqueResult",
    "CritiqueSpec",
    "DEFAULT_FORBIDDEN_PATTERNS",
    "Embedder",
    "GuardrailResult",
    "HMDCEngine",
    "Judge",
    "JudgeScore",
    "LexicalEmbedder",
    "RubricCriterion",
    "RubricJudge",
    "Verdict",
    "VerifierResult",
    "compare_pairwise",
    "cosine",
    "deterministic_guardrails",
    "information_density",
]
