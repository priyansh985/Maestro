"""Pre-execution critique gate tests (BP7): HMDC/verifiers on the live boundary.

The HMDC engine + environmental verifiers used to be an offline harness; BP7
wires them into the PolicyEnforcementPoint as the last check before a side
effect. These tests attack that wiring at the boundary:

* the deterministic stages (guardrails, environmental verifier) *deny
  autonomously* — a fact the model cannot argue with;
* a probabilistic-judge uncertainty *routes to a human* (escalates) rather than
  silently denying or silently allowing;
* a gate that raises fails closed.
"""
from __future__ import annotations

from maestro.critique import HMDCEngine, RubricJudge
from maestro.domains import NetworkMitigationVerifier
from maestro.security.action import ActionProposal, parse_proposal
from maestro.security.critique_gate import GateOutcome, HMDCGate
from maestro.security.enforcement import PolicyEnforcementPoint
from maestro.security.identity import CapabilityIssuer
from maestro.security.ledger import Ledger
from maestro.security.risk_engine import Decision, RiskInputs

KEY = "k" * 32
TENANT = "tenant-a"


def _risk(level: float) -> RiskInputs:
    return RiskInputs(level, level, level, level, level, level, level, 0.0)


def _proposal(intent: str = "read_flow_summary", target: str = "10.0.0.0/8",
              reason: str = "flow summary requested") -> ActionProposal:
    return parse_proposal({
        "intent": intent, "target": target, "reason": reason,
        "evidence_ids": ["alert:1"], "requested_ttl_seconds": 900,
    })


def _pep(gate=None, approver=None) -> tuple[PolicyEnforcementPoint, Ledger]:
    led = Ledger(key=KEY)
    adapters = {"read_flow_summary": lambda p: {"ok": True, "summary": "x"}}
    pep = PolicyEnforcementPoint(
        issuer=CapabilityIssuer(key=KEY), ledger=led,
        evidence_exists=lambda e: e == "alert:1",
        tenant=TENANT, adapters=adapters, approver=approver,
        pre_execution_gate=gate)
    return pep, led


# --------------------------------------------------------------------------- #
# PEP <- GateOutcome mapping (the fail-closed contract)
# --------------------------------------------------------------------------- #
def test_pass_verdict_executes_and_records_the_critique():
    pep, led = _pep(gate=lambda p, c: GateOutcome(True, False, "pass", "ok", {"verdict": "pass"}))
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert res.allowed and res.output["summary"] == "x"
    # The verdict is recorded on the authorized audit event (decision observability).
    assert led.events[-1].detail["critique"] == {"verdict": "pass"}


def test_deterministic_deny_verdict_blocks_the_side_effect():
    executed = []
    pep, _ = _pep(gate=lambda p, c: GateOutcome(False, False, "revise", "unsafe mitigation", {}))
    pep._adapters["read_flow_summary"] = lambda p: executed.append(1) or {"ok": True}
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("critique")
    assert "unsafe mitigation" in res.reason
    assert not executed  # the adapter never ran — denied before the side effect


def test_reject_verdict_denies_autonomously():
    pep, _ = _pep(gate=lambda p, c: GateOutcome(False, False, "reject", "guardrail leak", {}))
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed
    assert res.decision == Decision.DENY_AUTONOMOUS and "reject" in res.reason


def test_route_to_human_escalates_and_denies_without_an_approver():
    pep, _ = _pep(gate=lambda p, c: GateOutcome(False, True, "route_to_human", "judge disagreement", {}))
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed
    assert res.decision == Decision.REQUIRE_APPROVAL
    assert "routed to human" in res.reason


def test_route_to_human_executes_when_a_human_approves():
    pep, _ = _pep(
        gate=lambda p, c: GateOutcome(False, True, "route_to_human", "disagreement", {}),
        approver=lambda p, d, r: True)
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert res.allowed and res.output["summary"] == "x"


def test_a_gate_that_raises_fails_closed():
    def _boom(p, c):
        raise RuntimeError("gate exploded")

    pep, _ = _pep(gate=_boom)
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("critique")
    assert "gate exploded" in res.reason


def test_no_gate_is_a_no_op_boundary():
    pep, _ = _pep(gate=None)
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert res.allowed  # unchanged pre-BP7 behavior


# --------------------------------------------------------------------------- #
# HMDCGate — real engine + environmental verifier + guardrails
# --------------------------------------------------------------------------- #
def _hmdc_gate(**kw) -> HMDCGate:
    engine = HMDCEngine(
        judges=(RubricJudge("guardian-a"), RubricJudge("guardian-b")),
        task_gate=NetworkMitigationVerifier())
    return HMDCGate(engine, family="network-monitor", **kw)


def test_hmdc_gate_passes_an_appropriate_mitigation():
    gate = _hmdc_gate()
    p = _proposal("throttle_telemetry", "telemetry:ws-stream", "DoS matched; throttle stream")
    out = gate(p, {"alert_class": "dos", "grounding": ("dos: High packet flood",)})
    assert out.allow and out.verdict == "pass"


def test_hmdc_gate_vetoes_an_unsafe_mitigation_deterministically():
    # raise_thresholds during a DoS would blind the detector — the environmental
    # verifier vetoes it as a *fact*, so it is a deny (not an escalate).
    gate = _hmdc_gate()
    p = _proposal("raise_thresholds", "detection:thresholds", "raise thresholds")
    out = gate(p, {"alert_class": "dos", "grounding": ("dos: flood",)})
    assert not out.allow and not out.escalate
    assert out.verdict == "revise" and "not an appropriate" in out.reason


def test_hmdc_gate_rejects_a_justification_that_leaks_a_secret():
    # A guardrail hard-fail is dispositive regardless of the mitigation being
    # otherwise appropriate — HMDC Stage 1 on the live boundary.
    gate = _hmdc_gate()
    p = _proposal("throttle_telemetry", "telemetry:ws-stream",
                  "throttle; aws key AKIAIOSFODNN7EXAMPLE for the box")
    out = gate(p, {"alert_class": "dos", "grounding": ("dos: flood",)})
    assert not out.allow and not out.escalate and out.verdict == "reject"


def test_hmdc_gate_routes_to_human_when_no_cross_family_judge_exists():
    # A judge from the generator's own family is excluded (self-preference); if
    # none remain, the engine routes to a human — the gate escalates.
    engine = HMDCEngine(
        judges=(RubricJudge("network-monitor"),),  # same family as the candidate
        task_gate=NetworkMitigationVerifier())
    gate = HMDCGate(engine, family="network-monitor")
    p = _proposal("throttle_telemetry", "telemetry:ws-stream", "throttle stream")
    out = gate(p, {"alert_class": "dos", "grounding": ("dos: flood",)})
    assert not out.allow and out.escalate and out.verdict == "route_to_human"
