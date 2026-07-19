"""Tests for the critique-driven hardening of the enforcement gateway.

Covers the four corrections applied to ``PolicyEnforcementPoint``:
* action confidence profile (independent signals; raises scrutiny, never authorizes),
* autonomy budget / rate limiting (the ``BudgetAvailable`` conjunct),
* idempotency / exactly-once intent,
* structured, chain-of-thought-free decision card + action lifecycle state.
"""
from __future__ import annotations

import pytest

from maestro.security.action import ActionProposal, parse_proposal
from maestro.security.budget import AutonomyBudget, BudgetError
from maestro.security.confidence import (
    ConfidenceBand,
    ConfidenceSignals,
    action_confidence,
    confidence_band,
)
from maestro.security.enforcement import ActionState, PolicyEnforcementPoint
from maestro.security.identity import CapabilityIssuer
from maestro.security.ledger import Ledger
from maestro.security.risk_engine import Decision, RiskInputs

KEY = "k" * 32
TENANT = "tenant-a"


def _risk(level: float, u: float = 0.0) -> RiskInputs:
    return RiskInputs(level, level, level, level, level, level, level, u)


def _issuer() -> CapabilityIssuer:
    return CapabilityIssuer(key=KEY)


def _proposal(intent: str = "read_flow_summary", target: str = "10.0.0.0/8") -> ActionProposal:
    return parse_proposal({
        "intent": intent, "target": target, "reason": "test",
        "evidence_ids": ["alert:1"], "requested_ttl_seconds": 900,
    })


def _token_for(iss: CapabilityIssuer, p: ActionProposal):
    return iss.issue("agent:run1", p.capability, p.resource, TENANT, 900)


def _pep(**kw):
    led = Ledger(key=KEY)
    adapters = {
        "read_flow_summary": lambda p: {"ok": True, "summary": "x"},
        "block_source_ip": lambda p: {"ok": True, "blocked": p.target},
    }
    pep = PolicyEnforcementPoint(
        issuer=_issuer(), ledger=led,
        evidence_exists=lambda e: e in {"alert:1", "flow:1"},
        tenant=TENANT, adapters=adapters,
        approver=kw.pop("approver", None), budget=kw.pop("budget", None))
    return pep, led


# --------------------------------------------------------------------------- #
# Confidence profile
# --------------------------------------------------------------------------- #
def test_confidence_weights_and_bands():
    hi = ConfidenceSignals(1.0, 1.0, 1.0, 1.0, 1.0)
    lo = ConfidenceSignals(0.0, 0.0, 0.0, 0.0, 0.0)
    assert action_confidence(hi) == pytest.approx(1.0)
    assert action_confidence(lo) == pytest.approx(0.0)
    assert confidence_band(0.95) == ConfidenceBand.AUTOMATABLE
    assert confidence_band(0.80) == ConfidenceBand.APPROVAL
    assert confidence_band(0.60) == ConfidenceBand.REVERSIBLE_ONLY
    assert confidence_band(0.30) == ConfidenceBand.DENY


def test_confidence_signals_reject_out_of_range():
    with pytest.raises(ValueError):
        ConfidenceSignals(1.5, 0.5, 0.5, 0.5, 0.5)


def test_low_confidence_denies_even_at_low_risk():
    pep, _ = _pep()
    weak = ConfidenceSignals(0.1, 0.1, 0.1, 0.1, 0.1)  # C ~ 0.1 -> DENY band
    res = pep.authorize_and_execute(
        _proposal(), token=None, risk=_risk(1.0), actor="a", confidence=weak)
    assert not res.allowed and res.reason.startswith("confidence")


def test_mid_confidence_escalates_to_approval():
    # C ~ 0.80 -> APPROVAL band: a low-risk read is escalated to require approval.
    signals = ConfidenceSignals(0.8, 0.8, 0.8, 0.8, 0.8)
    denied, _ = _pep()
    iss = _issuer()
    p = _proposal()
    tok = _token_for(iss, p)  # escalation makes decision != ALLOW -> needs capability
    r1 = denied.authorize_and_execute(
        p, token=tok, risk=_risk(1.0), actor="a", confidence=signals)
    assert not r1.allowed and r1.reason.startswith("approval")
    approved, _ = _pep(approver=lambda *_: True)
    r2 = approved.authorize_and_execute(
        p, token=tok, risk=_risk(1.0), actor="a", confidence=signals)
    assert r2.allowed and r2.decision == Decision.REQUIRE_APPROVAL


def test_high_confidence_cannot_override_hard_deny():
    pep, _ = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    strong = ConfidenceSignals(1.0, 1.0, 1.0, 1.0, 1.0)  # AUTOMATABLE
    res = pep.authorize_and_execute(
        p, token=_token_for(iss, p), risk=_risk(5.0), actor="a", confidence=strong)
    assert not res.allowed and res.decision == Decision.EMERGENCY_CONTAINMENT


# --------------------------------------------------------------------------- #
# Autonomy budget / rate limiting
# --------------------------------------------------------------------------- #
def test_budget_blocks_after_max_calls():
    pep, _ = _pep(budget=AutonomyBudget(max_tool_calls=1))
    r1 = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    r2 = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert r1.allowed and not r2.allowed and r2.reason.startswith("budget")


def test_budget_spend_limit():
    pep, _ = _pep(budget=AutonomyBudget(max_spend=1.0))
    ok = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a", cost=0.6)
    over = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a", cost=0.6)
    assert ok.allowed and not over.allowed and "spend" in over.reason


def test_budget_not_consumed_on_denied_action():
    b = AutonomyBudget(max_tool_calls=5)
    pep, _ = _pep(budget=b)
    p = _proposal("block_source_ip", "203.0.113.0/24")
    pep.authorize_and_execute(p, token=None, risk=_risk(1.0), actor="a")  # denied: no cap
    assert b.usage["calls"] == 0  # denial costs nothing


def test_budget_rate_limit_window():
    b = AutonomyBudget(window_seconds=100.0, max_calls_per_window=2)
    b.check(now=1000.0)
    b.consume(now=1000.0)
    b.check(now=1001.0)
    b.consume(now=1001.0)
    with pytest.raises(BudgetError):
        b.check(now=1002.0)          # 3rd in window -> blocked
    b.check(now=1200.0)              # window elapsed -> allowed again


# --------------------------------------------------------------------------- #
# Idempotency / exactly-once
# --------------------------------------------------------------------------- #
def test_idempotency_blocks_duplicate_execution():
    pep, _ = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    tok = _token_for(iss, p)
    r1 = pep.authorize_and_execute(p, token=tok, risk=_risk(1.0), actor="a", idempotency_key="job-1")
    r2 = pep.authorize_and_execute(p, token=tok, risk=_risk(1.0), actor="a", idempotency_key="job-1")
    assert r1.allowed and not r2.allowed and r2.reason.startswith("idempotency")


def test_idempotency_key_not_recorded_on_denial():
    pep, _ = _pep()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    # first attempt denied (no capability) -> key must remain retryable
    d = pep.authorize_and_execute(p, token=None, risk=_risk(1.0), actor="a", idempotency_key="k1")
    assert not d.allowed
    iss = _issuer()
    ok = pep.authorize_and_execute(
        p, token=_token_for(iss, p), risk=_risk(1.0), actor="a", idempotency_key="k1")
    assert ok.allowed  # retry with a valid token succeeds


# --------------------------------------------------------------------------- #
# Decision card + lifecycle state (Decision Observability, no chain-of-thought)
# --------------------------------------------------------------------------- #
def test_decision_card_has_no_reasoning_and_carries_evidence():
    pep, _ = _pep()
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="agent:run1")
    card = res.decision_card
    assert res.state == ActionState.COMPLETED
    assert card["execution_status"] == "executed"
    assert card["evidence_ids"] == ["alert:1"]
    assert card["decision_id"] == res.event_id
    # No chain-of-thought / raw reasoning fields leak into the card.
    forbidden = {"chain_of_thought", "reasoning", "scratchpad", "prompt", "monologue"}
    assert forbidden.isdisjoint(card.keys())


def test_denied_card_marks_not_executed_and_state():
    pep, _ = _pep()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    res = pep.authorize_and_execute(p, token=None, risk=_risk(5.0), actor="a")
    assert res.state in {ActionState.DENIED, ActionState.ESCALATED}
    assert res.decision_card["execution_status"] == "not_executed"


def test_schema_denial_is_quarantined():
    pep, _ = _pep()
    res = pep.submit_raw("{not json", token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.state == ActionState.QUARANTINED
