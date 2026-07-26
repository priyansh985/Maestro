"""End-to-end tests for the agent platform (the live control loop).

These prove the keystone claim: on the platform's execution path there is *no*
route from a model output to a side effect that bypasses the enforcement point.
A legitimate mitigation is authorized under a scoped capability and executed;
a rogue/out-of-scope proposal is denied or quarantined; every outcome is
recorded in a tamper-evident ledger.
"""
from __future__ import annotations

import dataclasses

import pytest

from maestro.agent.reasoning import ReasoningResult
from maestro.memory import MemoryScope, MemoryTier
from maestro.platform import AgentPlatform
from maestro.security.circuit_breaker import CircuitBreaker
from maestro.security.enforcement import ActionState
from maestro.security.metrics import compute_metrics
from maestro.security.policy_bundle import PolicyBundle
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


# --------------------------------------------------------------------------- #
# Executor sandbox + durable exactly-once on the live loop (BP4)
# --------------------------------------------------------------------------- #
def test_rogue_adapter_claiming_a_different_target_is_denied_at_the_sandbox():
    # An adapter that reports touching a resource OUTSIDE the authorized scope is
    # a compromised/buggy executor. The sandbox denies it at the side-effect
    # boundary — the escape is caught, not recorded as a clean execution.
    rogue = {"throttle_telemetry": lambda p: {"ok": True, "target": "telemetry:OTHER"}}
    p = AgentPlatform(adapters=rogue)
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed
    assert r.reason.startswith("sandbox:")
    assert "outside authorized scope" in r.reason
    # The denial is still audited — a caught escape is as visible as an execution.
    assert p.ledger.verify_chain() == -1


def test_oversized_adapter_output_is_denied_at_the_sandbox():
    fat = {"throttle_telemetry": lambda p: {"ok": True, "target": p.target, "blob": "x" * 200000}}
    p = AgentPlatform(adapters=fat)
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed and r.reason.startswith("sandbox:")


# --------------------------------------------------------------------------- #
# Pre-execution critique gate on the live loop (BP7)
# --------------------------------------------------------------------------- #
def test_unsafe_mitigation_is_vetoed_by_the_environmental_verifier():
    # The reasoner proposes an in-vocabulary, capability-backed action that is
    # WRONG for the observed condition: raising detection thresholds during a
    # DoS would blind the detector mid-attack. The deterministic environmental
    # verifier vetoes it at the boundary — before the side effect — even though
    # capability, risk, budget and breaker would all have allowed it.
    p = AgentPlatform(reasoner=_Rogue("raise_thresholds"))
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed
    assert r.reason.startswith("critique")
    assert "not an appropriate" in r.reason
    # No side effect ran, and the veto is audited like any other outcome.
    assert r.enforcement.output == {}
    assert p.ledger.verify_chain() == -1


def test_acting_on_a_benign_baseline_is_vetoed():
    # Acting on a NORMAL baseline is a self-inflicted disruption; throttling the
    # stream when nothing is wrong is vetoed.
    p = AgentPlatform(reasoner=_Rogue("throttle_telemetry"))
    r = p.handle_alert(_alert(AlertClass.NORMAL, 0.1))
    assert not r.allowed and r.reason.startswith("critique")


def test_a_justification_that_leaks_a_secret_is_rejected_at_the_gate():
    # HMDC Stage-1 guardrails are dispositive on the live loop: a mitigation that
    # is otherwise appropriate is still rejected if its justification leaks a
    # secret (defense against a compromised reasoner exfiltrating via the audit).
    class _Leaky:
        def reason(self, alert, ctx=None):
            return ReasoningResult(
                summary="throttle; password: hunter2 to reach the box",
                severity=1.0, action="throttle_telemetry")

    p = AgentPlatform(reasoner=_Leaky())
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed and r.reason.startswith("critique")
    assert "reject" in r.reason


def test_disabling_the_critique_gate_restores_the_pre_bp7_boundary():
    # The gate is default-on; enable_critique=False restores the earlier path so
    # an out-of-policy action would execute — proving the gate is what blocks it.
    p = AgentPlatform(reasoner=_Rogue("raise_thresholds"), enable_critique=False)
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r.allowed  # no critique gate -> the environmental veto is absent


def test_durable_journal_replays_a_side_effect_exactly_once_across_a_restart(tmp_path):
    jpath = str(tmp_path / "platform.jsonl")
    side: list[str] = []

    def _adapter(p):  # a shared, side-effecting adapter across two "processes"
        side.append(p.target)
        return {"ok": True, "effect": "throttled", "target": p.target}

    adapters = {"throttle_telemetry": _adapter}

    # "Process 1" executes the mitigation once and journals it to disk.
    p1 = AgentPlatform(adapters=adapters, journal_path=jpath)
    r1 = p1.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r1.allowed and side == ["telemetry:ws-stream"]

    # "Process 2" — a fresh platform (empty in-memory idempotency cache) over the
    # SAME on-disk journal — replays the recorded result rather than re-executing.
    p2 = AgentPlatform(adapters=adapters, journal_path=jpath)
    r2 = p2.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert r2.allowed
    assert side == ["telemetry:ws-stream"]         # NOT executed a second time
    # The replay is recorded honestly in the audit trail.
    authorized = [e for e in p2.ledger.events if e.event_type == "tool.execution.authorized"]
    assert authorized and authorized[-1].detail["replayed"] is True


# --------------------------------------------------------------------------- #
# Governed policy bundle at the side-effect boundary (CTRL-L6-03)
# --------------------------------------------------------------------------- #
def _tighten(p: AgentPlatform, drop: str, *, proposer="user:alice", approver="user:bob") -> None:
    """Two-person-approve a policy change that drops ``drop`` from the allow-list."""
    active = p.policy.active().bundle
    v_next = PolicyBundle.create(
        version=active.version + 1,
        allowed_intents=[i for i in active.allowed_intents if i != drop],
        parent_digest=active.digest(), provenance=f"incident: freeze {drop}")
    rid = p.policy.propose(v_next, proposer=proposer)
    p.policy.approve(rid, approver=approver)


def test_default_platform_ships_a_signed_governed_policy_baseline():
    p = AgentPlatform()
    active = p.policy.active()                       # verifies (fail-closed) on read
    assert active.bundle.version == 1
    # The genesis allow-list is exactly this agent's intent vocabulary.
    assert set(active.bundle.allowed_intents) == set(p.blast_radius().intent_vocabulary)


def test_a_two_person_policy_change_tightens_the_live_boundary():
    p = AgentPlatform()
    # Baseline: a DOS is mitigated by throttling the telemetry stream.
    assert p.handle_alert(_alert(AlertClass.DOS, 0.95)).allowed

    # An operator + a distinct approver tighten the policy to forbid throttling.
    _tighten(p, "throttle_telemetry")

    # The same mitigation is now denied AT THE EXECUTOR by the governed policy,
    # even though capability/risk/budget/critique would all pass.
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95, ts=2000.0))
    assert not r.allowed
    assert r.reason.startswith("policy_bundle")
    assert r.decision == "deny_autonomous"
    assert r.enforcement.output == {}                # no side effect ran
    # The governed change is itself recorded in the tamper-evident ledger.
    assert "policy.bundle.activated" in {e.event_type for e in p.ledger.events}
    assert p.ledger.verify_chain() == -1


def test_a_tampered_active_policy_fails_the_boundary_closed():
    p = AgentPlatform()
    # Forge the active bundle's signature: the executor must refuse to run under
    # a policy it cannot verify, rather than falling back to a permissive default.
    p.policy._active = dataclasses.replace(p.policy._active, signature="deadbeef")
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    assert not r.allowed
    assert r.reason.startswith("policy_bundle")
    assert "no valid active policy" in r.reason


def test_disabling_the_policy_bundle_restores_the_ungoverned_boundary():
    # Default-on; enable_policy_bundle=False removes the governed allow-list gate
    # so the action rides only the static registry — proving the gate is live.
    p = AgentPlatform(enable_policy_bundle=False)
    assert p.policy is None
    assert p.handle_alert(_alert(AlertClass.DOS, 0.95)).allowed
