"""Unit tests for the agent memory + planner wiring."""
from __future__ import annotations

import pytest

from maestro.agent.memory import AgentMemory
from maestro.agent.parameter_tuning import ParameterTuning
from maestro.agent.planner import DEFAULT_ALLOWED_ACTIONS, Planner
from maestro.agent.reasoning import StubReasoner
from maestro.telemetry.detection import SecurityDetector
from maestro.telemetry.performance import PerformanceMonitor


def test_planner_step_baseline(tmp_path):
    pm = PerformanceMonitor()
    det = SecurityDetector(pm)
    mem = AgentMemory(tmp_path / "history.json")
    mem.load()
    tuning = ParameterTuning(mem, base_s=34.0, alpha_s=3.0)
    planner = Planner(detector=det, memory=mem, tuning=tuning,
                     reasoner=StubReasoner())
    plan = planner.step(pkt_rate_pps=200.0)
    assert plan.action in DEFAULT_ALLOWED_ACTIONS
    assert plan.capture.duration_s == pytest.approx(34.0)


def test_planner_rejects_unvalidated_when_validate_true(tmp_path):
    pm = PerformanceMonitor()
    det = SecurityDetector(pm)
    mem = AgentMemory(tmp_path / "history.json")
    mem.load()
    tuning = ParameterTuning(mem, base_s=34.0, alpha_s=3.0)

    class BadReasoner:
        def reason(self, alert, ctx=None):
            from maestro.agent.reasoning import ReasoningResult
            return ReasoningResult(summary="x", severity=1.0, action="rm -rf /")
    planner = Planner(detector=det, memory=mem, tuning=tuning,
                     reasoner=BadReasoner(), validate_plans=True)
    plan = planner.step(pkt_rate_pps=15000.0)
    assert plan.action == "noop"
    assert plan.validation_passed is False
    assert "rm" in plan.rejection_reason
