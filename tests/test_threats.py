"""Unit tests for the threat catalogue (Sec 3.2 Table 1 + Sec 4.3.2 Table 4)."""
from __future__ import annotations

import pytest

from maestro.maestro.risk_score import risk_score
from maestro.maestro.threats import load_threats, threat_by_id

EXPECTED_TABLE_4 = {
    1: 12, 2: 9, 3: 18, 4: 12, 5: 12, 6: 18, 7: 27, 8: 9, 9: 12, 10: 18,
}


def test_loads_ten_threats():
    threats = load_threats()
    assert len(threats) == 10
    ids = [t.id for t in threats]
    assert ids == list(range(1, 11))


@pytest.mark.parametrize("tid,expected", sorted(EXPECTED_TABLE_4.items()))
def test_table4_risk_scores(tid, expected):
    threats = load_threats()
    t = threat_by_id(threats, tid)
    assert t.risk_score == expected
    # Cross-check Eq. (1)
    assert t.risk_score == risk_score(t.likelihood, t.impact, t.exploitability)


def test_threat_7_resource_exhaustion():
    threats = load_threats()
    t = threat_by_id(threats, 7)
    assert t.name == "Resource Exhaustion"
    assert t.risk_score == 27  # highest in Table 4
    assert t.primary_layer == "L4"
    assert "L2" in t.cross_layers
    assert "L5" in t.cross_layers


def test_threat_8_knowledge_base_poisoning():
    threats = load_threats()
    t = threat_by_id(threats, 8)
    assert t.name == "Knowledge Base Poisoning"
    assert t.primary_layer == "L2"
    assert t.risk_score == 9
