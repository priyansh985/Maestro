"""Tests for the operational residual-risk engine.

Validates the exact TC2 (memory-poisoning) worked example from the SecOps
research so the formulas can't silently drift.
"""
from __future__ import annotations

import pytest

from maestro.security import (
    Decision,
    EnforcementLevel,
    RiskAssessment,
    RiskInputs,
    VerificationLevel,
    base_risk,
    control_effectiveness,
    decide,
    requires_capability,
    residual_risk,
    uncertainty_adjusted,
)
from maestro.security import RiskControl as Control

# TC2 memory poisoning assessed values.
TC2 = RiskInputs(
    likelihood=4, impact=5, exploitability=4, exposure=4,
    detectability_inverse=4, recoverability_inverse=3, blast_radius=4,
    uncertainty=0.25,
)


def test_base_risk_matches_worked_example():
    assert base_risk(TC2) == pytest.approx(4.15)


def test_uncertainty_adjusted_matches_worked_example():
    assert uncertainty_adjusted(TC2) == pytest.approx(4.3575)


def test_residual_unmitigated_is_critical():
    r = residual_risk(TC2, [])
    assert r == pytest.approx(4.3575)
    assert decide(r) == Decision.EMERGENCY_CONTAINMENT


def test_residual_mitigated_drops_to_low_moderate():
    # An enforced, adversarially-tested control with designed effectiveness 0.65.
    control = Control(designed_effectiveness=0.65,
                      enforcement=EnforcementLevel.SIDE_EFFECT_BOUNDARY,
                      verification=VerificationLevel.ADVERSARIAL)
    r = residual_risk(TC2, [control])
    assert r == pytest.approx(1.5251, abs=1e-3)
    assert decide(r) == Decision.ALLOW_WITH_SAFEGUARDS


def test_declared_untested_control_contributes_nothing():
    """A control that is only declared (or untested) has zero effect — this is
    the declaration-enforcement gap made quantitative."""
    declared = Control(designed_effectiveness=0.9,
                       enforcement=EnforcementLevel.DECLARED,
                       verification=VerificationLevel.NONE)
    assert declared.contribution == 0.0
    assert residual_risk(TC2, [declared]) == pytest.approx(uncertainty_adjusted(TC2))


def test_planner_only_control_is_half_weighted():
    # Enforcement at pre-planner (0.5) halves even a fully-designed,
    # adversarially-verified control: 1.0 * 0.5 * 1.0 = 0.5.
    pre_planner = Control(designed_effectiveness=1.0,
                          enforcement=EnforcementLevel.PRE_PLANNER,
                          verification=VerificationLevel.ADVERSARIAL)
    assert pre_planner.contribution == pytest.approx(0.5)


def test_control_effectiveness_capped():
    strong = [Control(1.0, EnforcementLevel.SIDE_EFFECT_BOUNDARY,
                      VerificationLevel.ADVERSARIAL) for _ in range(3)]
    assert control_effectiveness(strong) == pytest.approx(0.85)


@pytest.mark.parametrize("residual,expected", [
    (1.0, Decision.ALLOW),
    (1.49, Decision.ALLOW),
    (1.5, Decision.ALLOW_WITH_SAFEGUARDS),
    (2.49, Decision.ALLOW_WITH_SAFEGUARDS),
    (2.5, Decision.REQUIRE_APPROVAL),
    (3.49, Decision.REQUIRE_APPROVAL),
    (3.5, Decision.DENY_AUTONOMOUS),
    (4.24, Decision.DENY_AUTONOMOUS),
    (4.25, Decision.EMERGENCY_CONTAINMENT),
    (5.0, Decision.EMERGENCY_CONTAINMENT),
])
def test_decision_bands(residual, expected):
    assert decide(residual) == expected


def test_capability_required_override():
    assert requires_capability("code_execution") is True
    assert requires_capability("data_exfiltration") is True
    assert requires_capability("read_summary") is False


def test_risk_inputs_validate_scale():
    with pytest.raises(ValueError):
        RiskInputs(6, 5, 4, 4, 4, 3, 4)  # likelihood > 5
    with pytest.raises(ValueError):
        RiskInputs(4, 5, 4, 4, 4, 3, 4, uncertainty=1.5)  # uncertainty > 1


def test_control_designed_effectiveness_validated():
    with pytest.raises(ValueError):
        Control(designed_effectiveness=1.5)


def test_assessment_as_dict():
    d = RiskAssessment(TC2).as_dict()
    assert d["base_risk"] == pytest.approx(4.15)
    assert d["decision"] == Decision.EMERGENCY_CONTAINMENT.value
