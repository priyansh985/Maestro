"""HMDC critique tests (blueprint §5).

Prove the corrected behavior: deterministic guardrails are dispositive, semantic
alignment is a gate (not a weight a judge can override), cross-family judging is
enforced, judge disagreement routes to a human, and verbosity/position bias are
countered.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from maestro.critique import (
    Candidate,
    CritiqueSpec,
    HMDCEngine,
    JudgeScore,
    RubricCriterion,
    RubricJudge,
    Verdict,
    compare_pairwise,
    cosine,
)
from maestro.critique.embedding import LexicalEmbedder


# A fixed-score judge so we can script ensemble behavior deterministically.
@dataclass
class _FixedJudge:
    family: str
    value: float

    def score(self, candidate, spec) -> JudgeScore:
        return JudgeScore(self.family, {"fixed": self.value}, self.value)


_INTENT = "summarize the network anomaly and recommend throttling telemetry"
_GROUNDING = ("packet rate spiked sharply", "cpu saturated near 100 percent")
_RUBRIC = (RubricCriterion("relevance",
                           "addresses the network anomaly and recommends throttling telemetry"),)


def _spec(**kw) -> CritiqueSpec:
    base = {"intent": _INTENT, "grounding": _GROUNDING, "rubric": _RUBRIC}
    base.update(kw)
    return CritiqueSpec(**base)


_GOOD = ("The network anomaly is a sharp packet rate spike saturating cpu; "
         "recommend throttling telemetry.")


# --------------------------------------------------------------------------- #
# Stage 1: deterministic guardrails are DISPOSITIVE
# --------------------------------------------------------------------------- #
def test_guardrail_hard_fails_on_a_leaked_secret():
    engine = HMDCEngine([RubricJudge("judge-B")])
    leaky = Candidate(_GOOD + " aws key AKIAABCDEFGHIJKLMNOP", family="gen-A")
    result = engine.critique(leaky, _spec())
    assert result.verdict is Verdict.REJECT
    assert any("forbidden-pattern" in f for f in result.guardrails.failures)


def test_guardrail_overrides_everything_downstream():
    # A perfectly on-topic answer that leaks a private key is still rejected —
    # the deterministic gate is not something a good judge score can buy back.
    engine = HMDCEngine([_FixedJudge("judge-B", 1.0)])
    leaky = Candidate(_GOOD + "\n-----BEGIN RSA PRIVATE KEY-----", family="gen-A")
    result = engine.critique(leaky, _spec())
    assert result.verdict is Verdict.REJECT
    assert result.judge_scores == ()          # judges never ran


def test_non_json_output_is_rejected_when_json_required():
    engine = HMDCEngine([RubricJudge("judge-B")])
    result = engine.critique(Candidate("not json", family="gen-A"),
                             _spec(required_format="json"))
    assert result.verdict is Verdict.REJECT
    assert "format:not-json" in result.guardrails.failures


# --------------------------------------------------------------------------- #
# Stage 2: semantic alignment is a FLOOR (a gate), not a weighted term
# --------------------------------------------------------------------------- #
def test_semantic_drift_routes_to_revise_even_if_a_judge_would_love_it():
    # A high-scoring judge cannot rescue an off-topic answer: the semantic gate
    # short-circuits before the judges are consulted (no fixed weighting).
    engine = HMDCEngine([_FixedJudge("judge-B", 1.0)])
    off_topic = Candidate("today the weather is pleasant and the coffee was warm",
                          family="gen-A")
    result = engine.critique(off_topic, _spec())
    assert result.verdict is Verdict.REVISE
    assert result.judge_scores == ()          # judge never got a vote


# --------------------------------------------------------------------------- #
# Stage 3: cross-family judging is enforced
# --------------------------------------------------------------------------- #
def test_same_family_judge_is_excluded_and_routes_to_human():
    # The only judge shares the generator's family → self-preference risk → no
    # independent judge → route to a human.
    engine = HMDCEngine([RubricJudge("gen-A")])
    result = engine.critique(Candidate(_GOOD, family="gen-A"), _spec())
    assert result.verdict is Verdict.ROUTE_TO_HUMAN
    assert "gen-A" in result.excluded_same_family


def test_clears_all_stages_with_an_independent_judge():
    engine = HMDCEngine([RubricJudge("judge-B")])
    result = engine.critique(Candidate(_GOOD, family="gen-A"),
                             _spec(min_ensemble_score=0.1))
    assert result.verdict is Verdict.PASS
    assert result.judge_scores and result.judge_scores[0].judge_family == "judge-B"


# --------------------------------------------------------------------------- #
# Stage 4: ensemble is variance-aware (disagreement routes to a human)
# --------------------------------------------------------------------------- #
def test_judge_disagreement_routes_to_human():
    engine = HMDCEngine([_FixedJudge("judge-B", 0.9), _FixedJudge("judge-C", 0.2)])
    result = engine.critique(Candidate(_GOOD, family="gen-A"), _spec())
    assert result.verdict is Verdict.ROUTE_TO_HUMAN
    assert result.ensemble_variance > _spec().route_variance_threshold


def test_agreeing_judges_pass():
    engine = HMDCEngine([_FixedJudge("judge-B", 0.9), _FixedJudge("judge-C", 0.88)])
    result = engine.critique(Candidate(_GOOD, family="gen-A"), _spec())
    assert result.verdict is Verdict.PASS


def test_low_ensemble_score_routes_to_revise():
    engine = HMDCEngine([_FixedJudge("judge-B", 0.3), _FixedJudge("judge-C", 0.32)])
    result = engine.critique(Candidate(_GOOD, family="gen-A"),
                             _spec(min_ensemble_score=0.5))
    assert result.verdict is Verdict.REVISE


# --------------------------------------------------------------------------- #
# Bias countermeasures
# --------------------------------------------------------------------------- #
def test_verbosity_bias_is_countered_by_length_normalization():
    judge = RubricJudge("judge-B")
    spec = _spec()
    concise = Candidate(_GOOD, family="gen-A")
    padded = Candidate(
        _GOOD + " " + "furthermore incidentally parenthetically notwithstanding regardless " * 6,
        family="gen-A")
    assert judge.score(concise, spec).overall > judge.score(padded, spec).overall


def test_position_bias_is_neutralized_by_evaluating_both_orders():
    # A judge that always prefers whatever is shown first is a pure position bias.
    def first_preferring(_a: str, _b: str) -> str:
        return "first"
    assert compare_pairwise("apple", "banana", first_preferring) == "tie"

    # A genuine, order-independent preference yields a real winner.
    def prefers_correct(a: str, b: str) -> str:
        return "first" if "correct" in a else "second"
    assert compare_pairwise("the correct answer", "a wrong answer", prefers_correct) == "a"
    assert compare_pairwise("a wrong answer", "the correct answer", prefers_correct) == "b"


def test_lexical_cosine_sanity():
    emb = LexicalEmbedder()
    assert cosine(emb.embed("throttle telemetry now"),
                  emb.embed("throttle telemetry now")) == pytest.approx(1.0)
    assert cosine(emb.embed("throttle telemetry"), emb.embed("banana pancakes")) == 0.0
