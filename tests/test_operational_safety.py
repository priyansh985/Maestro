"""Circuit-breaker (loop detection) and ledger-derived operational metrics."""
from __future__ import annotations

import pytest

from maestro.security.action import parse_proposal
from maestro.security.circuit_breaker import CircuitBreaker
from maestro.security.enforcement import PolicyEnforcementPoint
from maestro.security.identity import CapabilityIssuer
from maestro.security.ledger import Ledger
from maestro.security.metrics import compute_metrics
from maestro.security.risk_engine import RiskInputs

KEY = "k" * 32
TENANT = "tenant-a"


def _risk(level: float) -> RiskInputs:
    return RiskInputs(level, level, level, level, level, level, level, 0.0)


def _proposal(intent="read_flow_summary", target="10.0.0.0/8"):
    return parse_proposal({"intent": intent, "target": target, "reason": "r",
                           "evidence_ids": ["alert:1"], "requested_ttl_seconds": 900})


# --------------------------------------------------------------------------- #
# Circuit breaker (unit)
# --------------------------------------------------------------------------- #
def test_breaker_trips_at_threshold():
    cb = CircuitBreaker(max_repeats=3)
    assert not cb.record_and_check("sig")   # 1
    assert not cb.record_and_check("sig")   # 2
    assert cb.record_and_check("sig")       # 3 -> trip
    assert cb.is_tripped("sig")


def test_breaker_signatures_independent():
    cb = CircuitBreaker(max_repeats=2)
    cb.record_and_check("a")
    assert not cb.record_and_check("b")     # different signature, own counter
    assert cb.record_and_check("a")         # 2nd "a" -> trip


def test_breaker_window_forgets_old_attempts():
    cb = CircuitBreaker(max_repeats=2, window_seconds=10.0)
    assert not cb.record_and_check("s", now=1000.0)
    # 20s later the first attempt is outside the window, so this is "the first".
    assert not cb.record_and_check("s", now=1020.0)


def test_breaker_reset():
    cb = CircuitBreaker(max_repeats=1)
    cb.record_and_check("s")
    assert cb.is_tripped("s")
    cb.reset("s")
    assert not cb.is_tripped("s")


def test_breaker_rejects_bad_threshold():
    with pytest.raises(ValueError):
        CircuitBreaker(max_repeats=0)


# --------------------------------------------------------------------------- #
# Circuit breaker (PEP integration)
# --------------------------------------------------------------------------- #
def _pep(**kw):
    led = Ledger(key=KEY)
    adapters = {"read_flow_summary": lambda p: {"ok": True, "summary": "x"}}
    adapters.update(kw.pop("adapters", {}))
    pep = PolicyEnforcementPoint(
        issuer=CapabilityIssuer(key=KEY), ledger=led,
        evidence_exists=lambda e: e in {"alert:1"},
        tenant=TENANT, adapters=adapters, **kw)
    return pep, led


def test_pep_circuit_breaker_halts_identical_loop():
    pep, _ = _pep(breaker=CircuitBreaker(max_repeats=3))
    r1 = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    r2 = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    r3 = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert r1.allowed and r2.allowed
    assert not r3.allowed and r3.reason.startswith("circuit_breaker")


def test_pep_circuit_breaker_distinguishes_arguments():
    pep, _ = _pep(breaker=CircuitBreaker(max_repeats=2))
    pep.authorize_and_execute(_proposal(target="10.0.0.0/8"), token=None,
                              risk=_risk(1.0), actor="a")
    # Different target -> different signature -> not tripped.
    r = pep.authorize_and_execute(_proposal(target="10.1.0.0/8"), token=None,
                                  risk=_risk(1.0), actor="a")
    assert r.allowed


# --------------------------------------------------------------------------- #
# Operational metrics from the ledger
# --------------------------------------------------------------------------- #
def test_metrics_from_ledger():
    pep, led = _pep(adapters={"open_incident_ticket": lambda p: {"ok": False}})
    iss = CapabilityIssuer(key=KEY)
    # 1 allow (read), 1 capability deny (block w/o token), 1 postcondition failure (ticket).
    pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    pep.authorize_and_execute(_proposal("block_source_ip", "203.0.113.0/24"),
                              token=None, risk=_risk(1.0), actor="a")
    tk = iss.issue("a", "cap:ticketing:create", "t", TENANT, 900)
    pep.authorize_and_execute(_proposal("open_incident_ticket", "t"),
                              token=tk, risk=_risk(1.0), actor="a")

    m = compute_metrics(led)
    assert m["total_actions"] == 3
    assert m["authorized"] == 1
    assert m["denied"] == 2
    assert m["denials_by_stage"] == {"capability": 1, "postcondition": 1}
    assert m["unsafe_action_rate"] == 0.0        # bypass proof: no unsafe execution
    assert m["tool_failure_rate"] == pytest.approx(0.5)  # 1 postcondition fail / (1 allow + 1)
    assert m["ledger_intact"] is True


def test_metrics_empty_ledger():
    m = compute_metrics(Ledger(key=KEY))
    assert m["total_actions"] == 0 and m["authorization_rate"] == 0.0
    assert m["ledger_intact"] is True
