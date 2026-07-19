"""Action confidence profile (Enforcement Plane).

A model saying "I am 95% confident" is **not** calibrated probability of being
correct — self-reported confidence collapses under missing information, prompt
injection, or distribution shift. So confidence here is built from *independently
observable* signals, never from the model's own claim:

    C_action = 0.30·E + 0.25·V + 0.20·P + 0.15·A + 0.10·H

* ``E`` evidence quality    — source trust, recency, corroboration.
* ``V`` validator agreement — schema validity + deterministic rule checks.
* ``P`` policy compatibility.
* ``A`` action reversibility / bounded blast radius.
* ``H`` historical reliability for this agent-task-tool combination.

The score **does not authorize** anything. It is one input the enforcement
point uses to *raise* scrutiny: low confidence can downgrade a permissive risk
band to approval-required or deny, but high confidence can never override a hard
rule (capability-required actions, risk hard-deny). Weights are domain-tunable.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "evidence_quality": 0.30,
    "validator_agreement": 0.25,
    "policy_compatibility": 0.20,
    "reversibility": 0.15,
    "historical_reliability": 0.10,
}


class ConfidenceBand(str, Enum):
    """Confidence bands (thresholds on ``C_action`` in ``[0, 1]``)."""

    DENY = "deny"                        # < 0.50
    REVERSIBLE_ONLY = "reversible_only"  # 0.50–0.74
    APPROVAL = "approval"                # 0.75–0.89
    AUTOMATABLE = "automatable"          # >= 0.90


@dataclass(frozen=True)
class ConfidenceSignals:
    """Independently observed signals in ``[0, 1]`` — not model self-report."""

    evidence_quality: float
    validator_agreement: float
    policy_compatibility: float
    reversibility: float
    historical_reliability: float

    def __post_init__(self) -> None:
        for name in CONFIDENCE_WEIGHTS:
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be in [0, 1], got {v}")


def action_confidence(signals: ConfidenceSignals) -> float:
    """Weighted action confidence ``C_action`` in ``[0, 1]``."""
    return sum(w * getattr(signals, name) for name, w in CONFIDENCE_WEIGHTS.items())


def confidence_band(score: float) -> ConfidenceBand:
    if score < 0.50:
        return ConfidenceBand.DENY
    if score < 0.75:
        return ConfidenceBand.REVERSIBLE_ONLY
    if score < 0.90:
        return ConfidenceBand.APPROVAL
    return ConfidenceBand.AUTOMATABLE
