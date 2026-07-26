"""Cross-domain verifier tests (blueprint §7) + HMDC environmental-gate wiring.

Each domain's deterministic verifier is exercised on a passing and a failing
case, and the §5 gap is shown closed: an HMDC engine with a domain task-gate
short-circuits a task-verification failure *before* the probabilistic judges.
"""
from __future__ import annotations

from maestro.critique import Candidate, CritiqueSpec, HMDCEngine, RubricJudge, Verdict
from maestro.domains import (
    CitationVerifier,
    DomainPack,
    NetworkMitigationVerifier,
    ReconciliationVerifier,
    SafetyEnvelopeVerifier,
    TestSuiteVerifier,
    finance_pack,
    healthcare_legal_pack,
    robotics_pack,
    software_engineering_pack,
)


def _cand(text: str) -> Candidate:
    return Candidate(text, family="gen-A")


# --------------------------------------------------------------------------- #
# Software engineering — tests are the verifier
# --------------------------------------------------------------------------- #
def test_test_suite_verifier_passes_when_all_green():
    v = TestSuiteVerifier(lambda code: [True, True, True])
    r = v.verify(_cand("def f(): return 1"))
    assert r.verified and r.signal == "test-suite"


def test_test_suite_verifier_fails_on_a_red_test():
    v = TestSuiteVerifier(lambda code: [True, False, True])
    r = v.verify(_cand("def f(): return 2"))
    assert not r.verified and "1/3" in r.reason


def test_test_suite_verifier_fails_when_no_tests_ran():
    assert not TestSuiteVerifier(lambda code: []).verify(_cand("x")).verified


# --------------------------------------------------------------------------- #
# Finance — double-entry reconciliation
# --------------------------------------------------------------------------- #
def test_reconciliation_passes_when_balanced():
    v = ReconciliationVerifier(max_amount=1000.0)
    ctx = {"postings": [{"debit": 100.0}, {"credit": 100.0}]}
    assert v.verify(_cand("transfer"), ctx).verified


def test_reconciliation_fails_when_unbalanced():
    v = ReconciliationVerifier()
    ctx = {"postings": [{"debit": 100.0}, {"credit": 90.0}]}
    assert not v.verify(_cand("transfer"), ctx).verified


def test_reconciliation_fails_over_limit():
    v = ReconciliationVerifier(max_amount=50.0)
    ctx = {"postings": [{"debit": 100.0}, {"credit": 100.0}]}
    r = v.verify(_cand("transfer"), ctx)
    assert not r.verified and "exceeds limit" in r.reason


# --------------------------------------------------------------------------- #
# Healthcare / legal — citation-backed grounding
# --------------------------------------------------------------------------- #
def test_citation_verifier_passes_when_grounded_and_cited():
    v = CitationVerifier(min_support=0.6)
    ctx = {"sources": ["the maximum transmission unit on this segment is 1500 bytes"]}
    r = v.verify(_cand("The maximum transmission unit is 1500 bytes [S1]."), ctx)
    assert r.verified


def test_citation_verifier_fails_on_uncited_claim():
    v = CitationVerifier()
    ctx = {"sources": ["mtu is 1500 bytes"]}
    assert not v.verify(_cand("The MTU is 1500 bytes."), ctx).verified   # no [..] marker


def test_citation_verifier_fails_on_hallucinated_content():
    v = CitationVerifier(min_support=0.6)
    ctx = {"sources": ["mtu is 1500 bytes"]}
    # Cited, but the content is unsupported by the source → low grounding.
    r = v.verify(_cand("The patient should double the anticoagulant dosage immediately [S1]."), ctx)
    assert not r.verified


# --------------------------------------------------------------------------- #
# Robotics — the safety envelope (spinal cord)
# --------------------------------------------------------------------------- #
def test_safety_envelope_passes_within_limits():
    v = SafetyEnvelopeVerifier({"velocity": (0.0, 2.0), "accel": (0.0, 1.0)})
    assert v.verify(_cand("move"), {"command": {"velocity": 1.5, "accel": 0.5}}).verified


def test_safety_envelope_vetoes_out_of_range():
    v = SafetyEnvelopeVerifier({"velocity": (0.0, 2.0)})
    r = v.verify(_cand("move"), {"command": {"velocity": 5.0}})
    assert not r.verified and "velocity" in r.reason


# --------------------------------------------------------------------------- #
# Network monitoring — the mitigation-policy veto (the reproduction's own domain)
# --------------------------------------------------------------------------- #
def _mitigation(intent: str) -> Candidate:
    return Candidate("mitigation rationale", family="network-monitor",
                     metadata={"intent": intent})


def test_mitigation_verifier_passes_an_appropriate_response():
    v = NetworkMitigationVerifier()
    r = v.verify(_mitigation("throttle_telemetry"), {"alert_class": "dos"})
    assert r.verified and r.signal == "mitigation-policy"


def test_mitigation_verifier_vetoes_threshold_raise_during_a_dos():
    # The unsafe case: raising thresholds mid-DoS blinds the detector.
    v = NetworkMitigationVerifier()
    r = v.verify(_mitigation("raise_thresholds"), {"alert_class": "dos"})
    assert not r.verified and "not an appropriate" in r.reason


def test_mitigation_verifier_vetoes_action_on_a_benign_baseline():
    v = NetworkMitigationVerifier()
    assert not v.verify(_mitigation("throttle_telemetry"), {"alert_class": "normal"}).verified
    assert v.verify(_mitigation("noop"), {"alert_class": "normal"}).verified


def test_mitigation_verifier_fails_closed_without_context():
    v = NetworkMitigationVerifier()
    assert not v.verify(_mitigation("noop"), {}).verified          # no alert class
    assert not v.verify(Candidate("x"), {"alert_class": "dos"}).verified  # no intent


def test_mitigation_verifier_rejects_an_unknown_alert_class():
    v = NetworkMitigationVerifier()
    r = v.verify(_mitigation("noop"), {"alert_class": "made_up"})
    assert not r.verified and "unknown alert class" in r.reason


# --------------------------------------------------------------------------- #
# Domain packs
# --------------------------------------------------------------------------- #
def test_packs_expose_pattern_and_verifier():
    packs = [
        software_engineering_pack(lambda c: [True]),
        finance_pack(max_amount=1000.0),
        healthcare_legal_pack(),
        robotics_pack({"velocity": (0.0, 2.0)}),
    ]
    patterns = {p.reasoning_pattern for p in packs}
    assert patterns == {"react", "plan_execute", "strict_rag", "htn"}
    for p in packs:
        assert isinstance(p, DomainPack)
        assert p.verifier.signal in p.summary() or p.reasoning_pattern in p.summary()


# --------------------------------------------------------------------------- #
# The §5 gap closed: environmental verification gates HMDC before the judges
# --------------------------------------------------------------------------- #
_SPEC = CritiqueSpec(intent="implement a function that returns the sum",
                     min_ensemble_score=0.0, min_semantic_alignment=0.0)


def test_hmdc_task_gate_rejects_failing_verification_before_judges():
    engine = HMDCEngine([RubricJudge("judge-B")],
                        task_gate=TestSuiteVerifier(lambda code: [True, False]))
    result = engine.critique(_cand("def add(a, b): return a - b"), _SPEC, context={})
    assert result.verdict is Verdict.REVISE
    assert result.task_verified is False
    assert result.judge_scores == ()          # judges never ran — verification is stronger


def test_hmdc_task_gate_lets_verified_output_reach_the_judges():
    engine = HMDCEngine([RubricJudge("judge-B")],
                        task_gate=TestSuiteVerifier(lambda code: [True, True]))
    result = engine.critique(_cand("implement a function that returns the sum"),
                             _SPEC, context={})
    assert result.task_verified is True
    assert result.verdict is Verdict.PASS
    assert result.judge_scores                # judges ran after verification passed


def test_hmdc_without_task_gate_leaves_task_verified_none():
    engine = HMDCEngine([RubricJudge("judge-B")])
    result = engine.critique(_cand("implement a function that returns the sum"), _SPEC)
    assert result.task_verified is None
