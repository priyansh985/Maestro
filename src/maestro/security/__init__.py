"""MAESTRO-SecOps security layer.

The first, self-contained slices of the security control plane (see
``docs/SECOPS.md``):

* :mod:`~maestro.security.risk_engine` — the operational residual-risk model
  (multi-dimensional risk, uncertainty penalty, evidence-weighted control
  effectiveness, residual->decision mapping). The paper's ``P x I x E`` score is
  preserved separately in :mod:`maestro.maestro.risk_score`.
* :mod:`~maestro.security.control_status` — the Phase-0 truth audit: an honest
  declared/implemented/enforced/tested/verified classification of every control
  the repo has, with a build-gating consistency invariant.
"""
from __future__ import annotations

from .control_status import (
    CONTROLS,
    Control,
    Status,
    audit_invariants,
    coverage_summary,
    to_report,
    write_report,
)
from .risk_engine import (
    CAPABILITY_REQUIRED_ACTIONS,
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
from .risk_engine import Control as RiskControl

__all__ = [
    # risk engine
    "RiskInputs",
    "RiskControl",
    "RiskAssessment",
    "EnforcementLevel",
    "VerificationLevel",
    "Decision",
    "base_risk",
    "uncertainty_adjusted",
    "control_effectiveness",
    "residual_risk",
    "decide",
    "requires_capability",
    "CAPABILITY_REQUIRED_ACTIONS",
    # control status (truth audit)
    "Control",
    "Status",
    "CONTROLS",
    "audit_invariants",
    "coverage_summary",
    "to_report",
    "write_report",
]
