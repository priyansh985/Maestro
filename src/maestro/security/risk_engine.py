"""Operational residual-risk model for MAESTRO-SecOps.

The paper's ordinal score ``R = P x I x E`` (see
:mod:`maestro.maestro.risk_score`) is kept intact for reproduction. This module
adds the *operational* risk model used to decide whether an autonomous agent
action may execute: a multi-dimensional base risk, an uncertainty penalty,
evidence-weighted control effectiveness, and a residual risk that maps to a
runtime decision.

All scalar dimensions are on a 1-5 scale; ``uncertainty`` is on ``[0, 1]``. The
formulas are documented in ``docs/SECOPS.md`` and validated against the paper's
TC2 (memory-poisoning) worked example in the tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# R_base weights. They sum to 1.0 so R_base stays on the 1-5 scale, with impact
# dominant and likelihood / exploitability / containment all material.
WEIGHTS: dict[str, float] = {
    "likelihood": 0.20,
    "impact": 0.25,
    "exploitability": 0.15,
    "exposure": 0.10,
    "detectability_inverse": 0.10,
    "recoverability_inverse": 0.10,
    "blast_radius": 0.10,
}

UNCERTAINTY_PENALTY = 0.20
#: No software control is credited with a perfect residual-risk reduction.
MAX_CONTROL_EFFECTIVENESS = 0.85


def _check_scale(name: str, value: float) -> None:
    if not 1 <= value <= 5:
        raise ValueError(f"{name} must be on the 1-5 scale, got {value}")


class EnforcementLevel(float, Enum):
    """Where a control actually runs (the ``e`` factor)."""

    SIDE_EFFECT_BOUNDARY = 1.0  # enforced at the executor/side-effect boundary
    PRE_PLANNER = 0.5           # advisory / planner-side only
    DECLARED = 0.0              # named but not wired to any enforcement point


class VerificationLevel(float, Enum):
    """How well a control is tested (the ``v`` factor)."""

    ADVERSARIAL = 1.0  # recent passing adversarial/bypass test
    UNIT = 0.5         # unit-test evidence only
    NONE = 0.0         # no test evidence


class Decision(str, Enum):
    """Runtime decision produced from a residual-risk score."""

    ALLOW = "allow"
    ALLOW_WITH_SAFEGUARDS = "allow_with_safeguards"
    REQUIRE_APPROVAL = "require_approval"
    DENY_AUTONOMOUS = "deny_autonomous"
    EMERGENCY_CONTAINMENT = "emergency_containment"


@dataclass
class RiskInputs:
    """Assessed risk dimensions for one threat/action (1-5, uncertainty 0-1)."""

    likelihood: float
    impact: float
    exploitability: float
    exposure: float
    detectability_inverse: float
    recoverability_inverse: float
    blast_radius: float
    uncertainty: float = 0.0

    def __post_init__(self) -> None:
        for name in WEIGHTS:
            _check_scale(name, getattr(self, name))
        if not 0.0 <= self.uncertainty <= 1.0:
            raise ValueError(f"uncertainty must be in [0, 1], got {self.uncertainty}")


@dataclass
class Control:
    """A control credited toward reducing residual risk.

    Effectiveness is only credited with evidence: a control that is declared
    but not enforced (``EnforcementLevel.DECLARED``) or untested
    (``VerificationLevel.NONE``) contributes zero — this is the mechanism that
    closes the "declaration-enforcement gap".
    """

    designed_effectiveness: float  # w in [0, 1]
    enforcement: EnforcementLevel = EnforcementLevel.DECLARED
    verification: VerificationLevel = VerificationLevel.NONE
    name: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.designed_effectiveness <= 1.0:
            raise ValueError("designed_effectiveness must be in [0, 1]")

    @property
    def contribution(self) -> float:
        return self.designed_effectiveness * float(self.enforcement) * float(self.verification)


def base_risk(inputs: RiskInputs) -> float:
    """Weighted base risk ``R_base`` on the 1-5 scale."""
    return sum(weight * getattr(inputs, name) for name, weight in WEIGHTS.items())


def uncertainty_adjusted(inputs: RiskInputs) -> float:
    """``R_uncertain = R_base * (1 + 0.20 * U)`` — penalize weak evidence."""
    return base_risk(inputs) * (1.0 + UNCERTAINTY_PENALTY * inputs.uncertainty)


def control_effectiveness(controls: list[Control]) -> float:
    """Evidence-weighted, capped total control effectiveness ``C_effective``."""
    total = sum(c.contribution for c in controls)
    return min(MAX_CONTROL_EFFECTIVENESS, total)


def residual_risk(inputs: RiskInputs, controls: list[Control] | None = None) -> float:
    """``R_residual = R_uncertain * (1 - C_effective)``."""
    c_eff = control_effectiveness(controls or [])
    return uncertainty_adjusted(inputs) * (1.0 - c_eff)


# Residual-risk -> runtime decision bands (docs/SECOPS.md § Risk-to-Action).
def decide(residual: float) -> Decision:
    if residual < 1.50:
        return Decision.ALLOW
    if residual < 2.50:
        return Decision.ALLOW_WITH_SAFEGUARDS
    if residual < 3.50:
        return Decision.REQUIRE_APPROVAL
    if residual < 4.25:
        return Decision.DENY_AUTONOMOUS
    return Decision.EMERGENCY_CONTAINMENT


#: Action classes that always require an explicit capability regardless of the
#: numeric score (the override rule in docs/SECOPS.md § Risk-to-Action).
CAPABILITY_REQUIRED_ACTIONS: frozenset[str] = frozenset({
    "credential_access",
    "code_execution",
    "data_exfiltration",
    "deletion",
    "irreversible_network_change",
    "cross_tenant_access",
    "sub_agent_delegation",
})


def requires_capability(action_class: str) -> bool:
    """True if the action may never be authorized on model confidence alone."""
    return action_class in CAPABILITY_REQUIRED_ACTIONS


@dataclass
class RiskAssessment:
    """Full assessment bundle for reporting/logging."""

    inputs: RiskInputs
    controls: list[Control] = field(default_factory=list)

    def as_dict(self) -> dict[str, float | str]:
        residual = residual_risk(self.inputs, self.controls)
        return {
            "base_risk": round(base_risk(self.inputs), 4),
            "uncertainty_adjusted": round(uncertainty_adjusted(self.inputs), 4),
            "control_effectiveness": round(control_effectiveness(self.controls), 4),
            "residual_risk": round(residual, 4),
            "decision": decide(residual).value,
        }
