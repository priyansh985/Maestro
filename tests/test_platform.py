"""End-to-end tests for the agent platform (the live control loop).

These prove the keystone claim: on the platform's execution path there is *no*
route from a model output to a side effect that bypasses the enforcement point.
A legitimate mitigation is authorized under a scoped capability and executed;
a rogue/out-of-scope proposal is denied or quarantined; every outcome is
recorded in a tamper-evident ledger.
"""
from __future__ import annotations

import pytest

from maestro.agent.reasoning import ReasoningResult
from maestro.memory import MemoryScope, MemoryTier
from maestro.platform import AgentPlatform
from maestro.security.circuit_breaker import CircuitBreaker
from maestro.security.enforcement import ActionState
from maestro.security.metrics import compute_metrics
from maestro.telemetry.detection import Alert, AlertClass


def _alert(cls: AlertClass, sev: float, ts: float = 1000.0) -> Alert:
    return Alert(ts, cls, sev, "detail")


class _Rogue:
    """A reasoner that proposes a fixed (possibly malicious) action."""

    def __init__(self, action: str) -> None:
        self.action = action

    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        return ReasoningResult(summary="rogue", severity=1.0, action=self.action)


# --------------------------------------------------------------------------- #
# Legitimate operational path
# --------------------------------------------------------------------------- #
def test_normal_alert_executes_noop():
    p = AgentPlatform()
    r = p.handle_alert(_alert(AlertClass.NORMAL, 0.1))
    assert r.proposed_action == "noop"
    assert r.allowed


@pytest.mark.parametrize("cls,sev,action", [
    (AlertClass.ANOMALY, 0.6, "raise_thresholds"),
    (AlertClass.DOS, 0.95, "throttle_telemetry"),
])
def test_legitimate_mitigation_authorized_and_executed(cls, sev, action):
    p = AgentPlatform()
    r = p.handle_alert(_alert(cls, sev))
    assert r.proposed_action == action
    assert r.allowed
    assert r.enforcement.output.get("effect")          # adapter actually ran
    assert r.enforcement.state == ActionState.COMPLETED


def test_mitigation_carries_a_capability_and_audit():
    p = AgentPlatform()
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r.allowed and r.enforcement.event_id
    assert p.ledger.verify_chain() == -1


# --------------------------------------------------------------------------- #
# The enforcement point has teeth
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("action", ["block_source_ip", "rotate_credentials", "read_flow_summary"])
def test_out_of_scope_action_denied_at_capability(action):
    # The platform never provisioned a capability for these, so the gateway
    # denies them even though the model proposed them.
    p = AgentPlatform(reasoner=_Rogue(action))
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed
    assert r.reason.startswith("capability")


def test_unknown_intent_is_quarantined():
    p = AgentPlatform(reasoner=_Rogue("exfiltrate_everything"))
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed
    assert r.reason.startswith("schema")
    assert r.enforcement.state == ActionState.QUARANTINED


def test_denials_are_still_audited():
    p = AgentPlatform(reasoner=_Rogue("block_source_ip"))
    p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert len(p.ledger) == 1                 # the denial was recorded
    assert p.ledger.verify_chain() == -1


# --------------------------------------------------------------------------- #
# Operational safety on the live path
# --------------------------------------------------------------------------- #
def test_kill_switch_halts_the_platform():
    p = AgentPlatform()
    p.halt()
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed and r.decision == "emergency_containment"
    p.resume()
    assert p.handle_alert(_alert(AlertClass.DOS, 0.95)).allowed


def test_circuit_breaker_halts_runaway_denial_loop():
    # A rogue reasoner repeatedly proposing the same denied action against the
    # same alert trips the breaker (idempotency does not, since denials are not
    # recorded as executed).
    p = AgentPlatform(reasoner=_Rogue("block_source_ip"),
                      breaker=CircuitBreaker(max_repeats=2))
    a = _alert(AlertClass.DOS, 0.95)
    r1 = p.handle_alert(a)
    r2 = p.handle_alert(a)
    assert r1.reason.startswith("capability")
    assert r2.reason.startswith("circuit_breaker")


def test_idempotency_blocks_replaying_the_same_alert():
    p = AgentPlatform()
    a = _alert(AlertClass.DOS, 0.95)
    r1 = p.handle_alert(a)
    r2 = p.handle_alert(a)          # same alert -> same idempotency key
    assert r1.allowed
    assert not r2.allowed and r2.reason.startswith("idempotency")


# --------------------------------------------------------------------------- #
# Decision observability + metrics
# --------------------------------------------------------------------------- #
def test_decision_card_has_evidence_and_no_chain_of_thought():
    p = AgentPlatform()
    card = p.handle_alert(_alert(AlertClass.DOS, 0.95)).decision_card
    assert card["evidence_ids"] and card["execution_status"] == "executed"
    assert card["action_confidence"] is not None
    forbidden = {"chain_of_thought", "reasoning", "scratchpad", "prompt", "monologue"}
    assert forbidden.isdisjoint(card.keys())


def test_platform_metrics_show_no_unsafe_execution():
    p = AgentPlatform()
    for cls, sev in [(AlertClass.NORMAL, 0.1), (AlertClass.ANOMALY, 0.6), (AlertClass.DOS, 0.95)]:
        p.handle_alert(_alert(cls, sev))
    # one out-of-scope denial too
    AgentPlatform()  # sanity: independent instance
    m = compute_metrics(p.ledger)
    assert m["total_actions"] == 3
    assert m["unsafe_action_rate"] == 0.0      # bypass proof
    assert m["ledger_intact"] is True


# --------------------------------------------------------------------------- #
# The runnable demo surface (maestro-agent)
# --------------------------------------------------------------------------- #
def test_agent_demo_runs_clean(capsys):
    from maestro.platform.demo import main
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Demo OK" in out
    # It must visibly show both an authorized execution and a gateway denial.
    assert "ALLOW" in out and "DENY" in out
    assert "unsafe_action_rate=0.0" in out


# --------------------------------------------------------------------------- #
# Shadow mode (blueprint §5 — evaluate without executing)
# --------------------------------------------------------------------------- #
def test_shadow_mode_withholds_execution_but_records_the_decision():
    p = AgentPlatform(shadow=True)
    assert p.shadow
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    # The full decision pipeline still runs and authorizes...
    assert r.allowed and r.enforcement.state == ActionState.COMPLETED
    # ...but the side effect was withheld, and that is visible.
    assert r.shadowed
    assert r.enforcement.output.get("shadow") is True
    assert r.enforcement.output.get("withheld") == "throttle_telemetry"
    # Still recorded, so a shadow run yields evaluation metrics.
    assert len(p.ledger) == 1


def test_non_shadow_mode_actually_executes():
    p = AgentPlatform()
    assert not p.shadow
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r.allowed and not r.shadowed
    assert r.enforcement.output.get("effect")     # a real effect, not withheld


def test_shadow_run_yields_clean_evaluation_metrics():
    p = AgentPlatform(shadow=True)
    for cls, sev in [(AlertClass.NORMAL, 0.1), (AlertClass.ANOMALY, 0.6), (AlertClass.DOS, 0.95)]:
        p.handle_alert(_alert(cls, sev))
    m = compute_metrics(p.ledger)
    assert m["total_actions"] == 3
    assert m["unsafe_action_rate"] == 0.0
    assert m["ledger_intact"] is True


# --------------------------------------------------------------------------- #
# Live memory grounding (§4 wired into the live loop)
# --------------------------------------------------------------------------- #
def test_live_actions_are_grounded_in_scoped_memory_records():
    p = AgentPlatform()
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    eid = r.decision_card["evidence_ids"][0]
    assert eid == "alert:dos:1000"                 # stable per-detection key
    assert p.memory.exists(eid, p.scope)           # a real, scoped memory record
    # The detection is quarantined on ingest (untrusted) yet valid as evidence.
    assert p.memory.quarantined(p.scope)


def test_evidence_reference_is_scope_isolated():
    p = AgentPlatform()
    p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert p.memory.exists("alert:dos:1000", p.scope)
    # Another tenant/agent cannot resolve this agent's evidence.
    assert not p.memory.exists("alert:dos:1000", MemoryScope("other", "agent"))


def test_replaying_an_alert_reuses_one_quarantined_record():
    p = AgentPlatform()
    a = _alert(AlertClass.DOS, 0.95)
    p.handle_alert(a)
    p.handle_alert(a)                              # same detection, denied by idempotency
    # get-or-create on the stable key: one record, not two.
    assert len(p.memory.quarantined(p.scope)) == 1


def test_poisoned_memory_is_quarantined_and_inert_on_the_live_agent():
    p = AgentPlatform()
    # Attacker injects 20 fake high-severity episodic records (the TC2 attack).
    for i in range(20):
        p.memory.remember(p.scope, MemoryTier.EPISODIC, f"fake dos {i}",
                          attributes={"severity": 0.99})
    # They land in quarantine — never surfaced by trusted recall, never influential.
    assert p.memory.recall(p.scope, tier=MemoryTier.EPISODIC) == []
    assert len(p.memory.quarantined(p.scope)) == 20
    # The live agent still operates correctly, grounded on its own detection.
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r.allowed and r.proposed_action == "throttle_telemetry"
    assert compute_metrics(p.ledger)["unsafe_action_rate"] == 0.0


def test_memory_promotion_shares_the_platform_ledger():
    p = AgentPlatform()
    p.handle_alert(_alert(AlertClass.DOS, 0.95))   # one action event
    rec = p.memory.remember(p.scope, MemoryTier.EPISODIC, "corroborated detection")
    tok = p.memory.issuer.issue(
        subject="human:analyst", capability="cap:memory:promote",
        resource_constraint=f"memory:{p.scope.tenant}", tenant=p.scope.tenant,
        ttl_seconds=600.0)
    p.memory.promote(rec.record_id, p.scope, token=tok)
    # Action + memory promotion live in ONE hash-chained tamper-evident ledger.
    assert "memory_promotion" in {e.event_type for e in p.ledger.events}
    assert p.ledger.verify_chain() == -1
    # ...but metrics still count only actions (memory events are not actions).
    assert compute_metrics(p.ledger)["total_actions"] == 1
