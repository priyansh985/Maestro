"""SOC Network Monitoring Vertical (BP5).

This vertical exercises the entire enforcement spine by composing the AgentPlatform
with a dedicated SOCReasoner that natively analyzes the evidence graph.
"""
from __future__ import annotations

from maestro.agent.reasoning import ReasoningResult
from maestro.platform.agent_platform import AgentPlatform
from maestro.telemetry.detection import Alert, AlertClass


class SOCReasoner:
    """A specialized reasoner for the SOC vertical.
    
    It analyzes the incoming alert alongside the trusted evidence graph to
    recommend actions like `promote_memory` or `throttle_telemetry`.
    """
    def reason(self, alert: Alert, ctx: dict | None = None) -> ReasoningResult:
        graph = ctx.get("evidence_graph", []) if ctx else []
        
        # If the alert is anomalous but we have previous trusted context,
        # we might escalate. But for BP5, let's demonstrate the memory promotion
        # pipeline: if it's a known benign alert we ignore it, but if we lack context
        # and see a DoS, we might first promote the alert or throttle.
        if alert.cls == AlertClass.DOS:
            # Check if we already have throttled recently (evidence graph)
            throttled_recently = any(
                "throttle" in r.content.lower() for r in graph
            )
            if throttled_recently:
                return ReasoningResult(
                    summary="DoS persists despite throttling. Escalating to operator.",
                    severity=alert.severity + 0.1,
                    action="alert_operator"
                )
            return ReasoningResult(
                summary="DoS signature detected. Proposing telemetry throttle.",
                severity=alert.severity,
                action="throttle_telemetry"
            )
            
        if alert.cls == AlertClass.ANOMALY:
            return ReasoningResult(
                summary="Anomaly detected. Proposing threshold raise.",
                severity=alert.severity,
                action="raise_thresholds"
            )
            
        return ReasoningResult(
            summary="Baseline conditions. No action.",
            severity=alert.severity,
            action="noop"
        )


def create_soc_agent(tenant: str = "default", controller: str = "human:operator") -> AgentPlatform:
    """Instantiate the SOC Vertical agent with its restricted vocabulary."""
    vocabulary = [
        "noop", "throttle_telemetry", "raise_thresholds", 
        "raise_capture_duration", "alert_operator", "promote_memory"
    ]
    return AgentPlatform(
        reasoner=SOCReasoner(),
        tenant=tenant,
        controller=controller,
        agent_id="agent:soc-network-monitor:run",
        allowed_intents=vocabulary,
        # The PEP and sandbox wrap this agent automatically.
    )
