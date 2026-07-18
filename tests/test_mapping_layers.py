"""Tests for the MAESTRO layer declaration, mapping, and mitigation catalogue.

Covers Sec 4.1 (seven layers L1..L7), Sec 4.2 Table 2 (threat->layer mapping)
and Sec 5.1-5.3 (defense-in-depth mitigations).
"""
from __future__ import annotations

from maestro.maestro.layers import LAYERS, abbrev_to_code
from maestro.maestro.mapping import layer_name, threat_risk_matrix, threat_to_layers
from maestro.maestro.mitigation import all_defenses, defenses_for_layer
from maestro.maestro.threats import load_threats


def test_seven_layers_l1_to_l7():
    codes = [li.code for li in LAYERS]
    assert codes == ["L1", "L2", "L3", "L4", "L5", "L6", "L7"]
    assert all(li.name and li.role for li in LAYERS)


def test_layer_name_and_abbrev_roundtrip():
    assert layer_name("L1") == "Foundation Models"
    assert layer_name("L7") == "Agent Ecosystem"
    assert layer_name("unknown") == "unknown"  # graceful passthrough
    for li in LAYERS:
        assert abbrev_to_code(li.name) == li.code
    assert abbrev_to_code("Nonexistent") == "Nonexistent"


def test_threat_to_layers_rows():
    threats = load_threats()
    rows = threat_to_layers(threats)
    assert len(rows) == 10
    assert all("Primary Layer" in r and "Cross-Layer Impact" in r for r in rows)
    # Primary layer is rendered as "L4 - Deployment & Infrastructure" etc.
    assert any(str(r["Primary Layer"]).startswith("L4 - ") for r in rows)


def test_threat_risk_matrix_scores():
    threats = load_threats()
    rows = threat_risk_matrix(threats)
    assert len(rows) == 10
    by_id = {r["Threat"].split(".")[0]: r for r in rows}
    assert by_id["7"]["Risk Score"] == 27
    assert by_id["8"]["Risk Score"] == 9


def test_mitigations_cover_every_layer():
    catalogue = all_defenses()
    assert set(catalogue) == {li.code for li in LAYERS}
    for code, controls in catalogue.items():
        assert controls, f"layer {code} has no mitigations"
        assert all(m.layer == code for m in controls)
    assert defenses_for_layer("L2")  # memory isolation lives here (Sec 5.3)
    assert defenses_for_layer("ZZ") == []
