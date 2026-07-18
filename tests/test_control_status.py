"""Tests for the Phase-0 control-status truth audit."""
from __future__ import annotations

import json

from maestro.security.control_status import (
    CONTROLS,
    Control,
    Status,
    audit_invariants,
    coverage_summary,
    to_report,
    write_report,
)


def test_inventory_is_self_consistent():
    """Our own inventory must pass the evidence-consistency invariant."""
    assert audit_invariants(CONTROLS) == []


def test_all_controls_have_valid_shape():
    ids = [c.control_id for c in CONTROLS]
    assert len(ids) == len(set(ids))  # unique
    for c in CONTROLS:
        assert isinstance(c.status, Status)
        assert c.maestro_layer in {"L1", "L2", "L3", "L4", "L5", "L6", "L7"}


def test_coverage_counts_add_up():
    cov = coverage_summary(CONTROLS)
    assert cov["total"] == len(CONTROLS)
    assert sum(cov["by_status"].values()) == len(CONTROLS)  # type: ignore[union-attr]
    assert 0.0 <= cov["enforcement_ratio"] <= 1.0  # type: ignore[operator]


def test_no_control_claims_enforced_while_disabled():
    # This is the core honesty guard: default-off is never "enforced".
    for c in CONTROLS:
        if c.status == Status.ENFORCED:
            assert c.default_state != "disabled"


def test_invariant_flags_tested_without_test_id():
    bad = [Control("X", "n", "L1", Status.TESTED, "enabled",
                   "impl.py:x", "impl.py:x", test_id=None)]
    violations = audit_invariants(bad)
    assert any("no test_id" in v for v in violations)


def test_invariant_flags_enforced_while_disabled():
    bad = [Control("Y", "n", "L2", Status.ENFORCED, "disabled",
                   "gate.py:enforce", "gate.py:enforce", test_id="t")]
    violations = audit_invariants(bad)
    assert any("default_state is disabled" in v for v in violations)


def test_invariant_flags_implemented_without_implementation():
    bad = [Control("Z", "n", "L3", Status.IMPLEMENTED, "enabled",
                   None, implementation=None, test_id=None)]
    violations = audit_invariants(bad)
    assert any("no implementation" in v for v in violations)


def test_write_report(tmp_path):
    path = write_report(tmp_path)
    assert path.exists()
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.0"
    assert len(report["controls"]) == len(CONTROLS)
    assert report["violations"] == []
    assert report["coverage"]["total"] == len(CONTROLS)


def test_to_report_shape():
    r = to_report()
    assert set(r) == {"schema_version", "controls", "coverage", "violations"}


def test_audit_cli_main_returns_zero(capsys):
    from maestro.security.audit import main
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Audit OK" in out
