"""Eq. (1) of arXiv:2508.10043 — qualitative -> ordinal risk scoring.

Equation (Sec 4.3)::
    R = P x I x E

Each dimension takes an ordinal on {1 (Low, 2 (Medium), 3 (High)} (Table 3).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Qualitative = Literal["low", "medium", "high"]

_ORDINAL: dict[str, int] = {"low": 1, "medium": 2, "high": 3}  # Sec 4.3 Table 3


@dataclass(frozen=True)
class RiskComponents:
    """P, I, E for Eq. (1)."""
    likelihood: Qualitative
    impact: Qualitative
    exploitability: Qualitative

    def ordinals(self) -> tuple[int, int, int]:
        return (_ORDINAL[self.likelihood], _ORDINAL[self.impact], _ORDINAL[self.exploitability])


def qualitative_to_ordinal(q: Qualitative) -> int:
    """Implements Table 3 mapping."""
    if q not in _ORDINAL:
        raise ValueError(f"Qualitative must be in {set(_ORDINAL)} - got {q}")
    return _ORDINAL[q]


def risk_score(p: Qualitative, i: Qualitative, e: Qualitative) -> int:
    """Eq. (1) result R = P*I*E (Sec 4.3)."""
    return qualitative_to_ordinal(p) * qualitative_to_ordinal(i) * qualitative_to_ordinal(e)


def risk_score_components(rc: RiskComponents) -> int:
    """Convenience overload taking a :class:`RiskComponents`."""
    p, i, e = rc.ordinals()
    return p * i * e


def parse_risk(score: int) -> str:
    """Bucket an integer risk score into Low / Moderate / High priority.

    Mirrors the three illustrative buckets in Sec 4.3.1: ``R = 3`` is *low*,
    ``R = 8`` is *moderate*, and ``R = 9`` is a *high priority area*. The
    boundaries below reproduce those three anchor points exactly: ``< 6`` Low,
    ``< 9`` Moderate, ``>= 9`` High.
    """
    if score < 6:
        return "Low"
    if score < 9:
        return "Moderate"
    return "High"
