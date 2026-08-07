"""Tests for the Evidence Graph and Memory Promotion pipeline (BP5).

Ensures that the SOC vertical respects the quarantine paradox:
- Untrusted memory is not included in the evidence graph.
- Promoted memory is successfully retrieved and supplied to the reasoner.
- `promote_memory` intent operates successfully through the PEP.
"""

from maestro.agent.reasoning import ReasoningResult
from maestro.memory import MemoryTier
from maestro.platform import AgentPlatform
from maestro.telemetry.detection import Alert, AlertClass


def _alert(cls: AlertClass, sev: float, ts: float = 1000.0) -> Alert:
    return Alert(ts, cls, sev, "detail")


class _GraphSpy:
    """A reasoner spy that records what it was given."""
    def __init__(self, action: str = "noop"):
        self.action = action
        self.last_graph = None
        
    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        if ctx and "evidence_graph" in ctx:
            self.last_graph = ctx["evidence_graph"]
        else:
            self.last_graph = []
        return ReasoningResult(summary="spy", severity=1.0, action=self.action)


def test_evidence_graph_excludes_untrusted_memory():
    spy = _GraphSpy("throttle_telemetry")
    p = AgentPlatform(reasoner=spy)
    
    # Inject untrusted memory (the quarantine paradox test)
    for i in range(5):
        p.memory.remember(p.scope, MemoryTier.EPISODIC, f"fake alert {i}")
        
    p.handle_alert(_alert(AlertClass.DOS, 0.95))
    
    # The spy should have received an empty evidence graph
    assert spy.last_graph == []


def test_evidence_graph_includes_promoted_memory():
    spy = _GraphSpy("throttle_telemetry")
    p = AgentPlatform(reasoner=spy)
    
    # Create an episodic memory and promote it
    rec = p.memory.remember(p.scope, MemoryTier.EPISODIC, "trusted context")
    tok = p.memory.issuer.issue(
        subject="human:operator", capability="cap:memory:promote",
        resource_constraint=f"memory:{p.scope.tenant}", tenant=p.scope.tenant,
        ttl_seconds=600.0)
    p.memory.promote(rec.record_id, p.scope, token=tok)
    
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    
    # The spy should have received the promoted memory
    assert spy.last_graph is not None
    assert len(spy.last_graph) == 1
    assert spy.last_graph[0].record_id == rec.record_id
    
    # The evidence_ids in the platform result should include BOTH the new alert and the graph
    evidence_ids = r.decision_card["evidence_ids"]
    assert len(evidence_ids) == 2
    assert "alert:dos:1000" in evidence_ids
    assert rec.record_id in evidence_ids


def test_promote_memory_action_is_authorized_and_executed():
    spy = _GraphSpy("promote_memory")
    # For testing, we ensure 'promote_memory' is in the allowed intents (it is by default now if in vocabulary).
    # AgentPlatform uses its default vocabulary which now includes promote_memory.
    # Wait, the default agent doesn't have promote_memory in its default allowed_intents unless we specify it.
    vocabulary = [
        "noop", "throttle_telemetry", "raise_thresholds", 
        "raise_capture_duration", "alert_operator", "rollback_telemetry",
        "promote_memory"
    ]
    p = AgentPlatform(reasoner=spy, allowed_intents=vocabulary)
    r = p.handle_alert(_alert(AlertClass.DOS, 0.95))
    
    assert r.proposed_action == "promote_memory"
    assert r.allowed
    assert r.enforcement.output.get("effect") == "memory promoted"
