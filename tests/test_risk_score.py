"""Unit tests for the MAESTRO risk score (Sec 4.3 Eq. (1) + Table 3)."""
from __future__ import annotations

import pytest

from maestro.maestro.risk_score import (
    parse_risk, qualitative_to_ordinal, risk_score, risk_score_components,
    RiskComponents)


def test_ordinal_table3():
    assert qualitative_to_ordinal("low") == 1
    assert qualitative_to_ordinal("medium") == 2
    assert qualitative_to_ordinal("high") == 3
    with pytest.raises(ValueError):
        qualitative_to_ordinal("critical")  # type: ignore[arg-type]


def test_eq1_illustrative_examples_sec431():
    # Sec 4.3.1 examples
    assert risk_score("low", "low", "high") == 1 * 1 * 3  # R = 3 (low)
    assert risk_score("medium", "medium", "medium") == 2 * 2 * 2  # R = 8 (moderate)
    assert risk_score("high", "high", "low") == 3 * 3 * 1  # R = 9 (high)


def test_eq1_dataclass():
    rc = RiskComponents(likelihood="high", impact="high", exploitability="high")
    assert risk_score_components(rc) == 27


def test_parse_risk_buckets_sec431():
    assert parse_risk(3) == "Low"
    assert parse_risk(8) == "Moderate"
    assert parse_risk(9) == "Moderate"
    assert parse_risk(18) == "High"
    assert parse_risk(27) == "High"
