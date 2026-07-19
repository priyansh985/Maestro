"""Operational security metrics, computed from the audit ledger.

The blueprint asks for a metrics view; the earlier critique sharpened *which*
metrics matter for a security control plane. Both are answered here by deriving
metrics from the tamper-evident ledger (`ledger.py`) rather than from a
self-reported dashboard counter — the numbers are as trustworthy as the log,
and the log's integrity is itself checked (`ledger_intact`).

Only metrics that are *honestly derivable* from what the gateway records are
computed. Task-completion / grounded-answer / memory-contamination rates need
goal labels and a memory subsystem this repo does not yet have, and are
deliberately omitted rather than faked.
"""
from __future__ import annotations

from collections import Counter

from .enforcement import _HARD_DENY
from .ledger import Ledger

_AUTHORIZED = "tool.execution.authorized"
_DENIED = "tool.execution.denied"
#: Denial stages that represent a tool-level failure rather than a policy block.
_TOOL_FAILURE_STAGES = {"execution", "postcondition"}
_HARD_DENY_VALUES = {d.value for d in _HARD_DENY}


def compute_metrics(ledger: Ledger) -> dict[str, object]:
    """Derive operational security metrics from a ledger's recorded events."""
    events = ledger.events
    authorized = [e for e in events if e.event_type == _AUTHORIZED]
    denied = [e for e in events if e.event_type == _DENIED]
    total = len(authorized) + len(denied)

    stages = Counter(str(e.detail.get("stage", "unknown")) for e in denied)
    tool_failures = sum(stages[s] for s in _TOOL_FAILURE_STAGES)
    tool_attempts = len(authorized) + tool_failures

    # Invariant proof: an executed action must never carry a hard-deny decision.
    unsafe_executed = sum(1 for e in authorized if e.decision in _HARD_DENY_VALUES)

    def rate(num: int, den: int) -> float:
        return round(num / den, 4) if den else 0.0

    return {
        "total_actions": total,
        "authorized": len(authorized),
        "denied": len(denied),
        "authorization_rate": rate(len(authorized), total),
        "denials_by_stage": dict(stages),
        # Executed actions that were in a hard-deny band — must be 0 (bypass proof).
        "unsafe_action_rate": rate(unsafe_executed, len(authorized)),
        "unsafe_executed_count": unsafe_executed,
        # Tool-level reliability (adapter raised / postcondition failed).
        "tool_failure_rate": rate(tool_failures, tool_attempts),
        # Share of denials that were policy blocks vs tool failures.
        "policy_block_count": len(denied) - tool_failures,
        "ledger_intact": ledger.verify_chain() == -1,
    }
