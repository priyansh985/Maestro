"""Planner module (Sec 3.1 + Sec 5.3 L3 — planner validation).

The planner reconciles telemetry -> detector -> reasoner -> parameter
tuning and produces actions. When ``mitigation.planner_validation`` is
enabled (Sec 5.3 L3), the plan produced is constrained to a whitespace of
allowable actions against an allowlist.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..telemetry.detection import SecurityDetector
from ..telemetry.performance import PerformanceMonitor
from .memory import AgentMemory
from .parameter_tuning import CaptureParams, ParameterTuning
from .reasoning import Reasoner, StubReasoner

# Sec 5.3 L3 allow-list of acceptable agent actions
DEFAULT_ALLOWED_ACTIONS: set[str] = {
    "noop",
    "throttle_telemetry",
    "raise_thresholds",
    "raise_capture_duration",
    "alert_operator",
    "rollback_telemetry",
}


@dataclass
class Plan:
    """Output of the planning step (Sec 3.1 「interactive」)."""
    summary: str
    action: str
    severity: float
    capture: CaptureParams
    samples_reasoning_latency_ms: float = 0.0
    validation_passed: bool = True
    rejection_reason: str = ""


class Planner:
    """Sec 3.1 control loop: telemetry -> detector -> reasoner -> action."""

    def __init__(self, detector: SecurityDetector,
                 memory: AgentMemory,
                 tuning: ParameterTuning,
                 reasoner: Reasoner | None = None,
                 allowed_actions: set[str] | None = None,
                 validate_plans: bool = False):
        self.detector = detector
        self.memory = memory
        self.tuning = tuning
        self.reasoner = reasoner or StubReasoner()
        self.allowed_actions = allowed_actions or set(DEFAULT_ALLOWED_ACTIONS)
        self.validate_plans = validate_plans
        self.history: list[Plan] = []

    def step(self, pkt_rate_pps: float) -> Plan:
        alert = self.detector.evaluate(pkt_rate_pps)
        result = self.reasoner.reason(alert)
        cap = self.tuning.tune_capture_duration()
        action = result.action
        passed = True
        reason = ""
        if self.validate_plans and action not in self.allowed_actions:
            passed = False
            reason = f"action '{action}' not in allow-list {sorted(self.allowed_actions)}"
            action = "noop"
        plan = Plan(
            summary=result.summary,
            action=action,
            severity=result.severity * alert.severity,
            capture=cap,
            samples_reasoning_latency_ms=result.latency_ms,
            validation_passed=passed,
            rejection_reason=reason,
        )
        self.history.append(plan)
        self.memory.append_alert_if(alert_cls=alert.cls.value,
                                    severity=alert.severity,
                                    detail=alert.detail)
        return plan

    @property
    def perf(self) -> PerformanceMonitor:
        return self.detector.perf
