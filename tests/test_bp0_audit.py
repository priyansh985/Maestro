"""Tests for the BP0 truth-audit generator (docs/audit/ ground truth).

The audit artifacts are only useful if they are *generated from the live code*
and stay internally consistent. These tests guard that contract: the generator
runs, is deterministic, and its curated maps agree with the code they describe.
"""
from __future__ import annotations

import json

import pytest

from maestro.platform.agent_platform import _INTENT_RESOURCE, default_tool_adapters
from maestro.scripts import bp0_audit
from maestro.security.control_status import to_report


def test_module_inventory_covers_the_package() -> None:
    rows = bp0_audit.module_inventory()
    modules = {r["module"] for r in rows}
    # Anchors across the enforcement plane, platform, and taxonomy must appear.
    for expected in (
        "maestro.security.control_status",
        "maestro.security.enforcement",
        "maestro.platform.agent_platform",
        "maestro.memory.store",
        "maestro.maestro.threats",
    ):
        assert expected in modules, f"{expected} missing from module inventory"
    assert all(int(r["lines"]) > 0 for r in rows)


def test_endpoint_inventory_flags_mutating_routes() -> None:
    rows = bp0_audit.endpoint_inventory()
    routes = {(r["method"], r["route"]) for r in rows}
    # The kill switch and the alert intake are mutating control-plane routes.
    assert ("POST", "/alert") in routes
    assert ("POST", "/halt") in routes
    for r in rows:
        assert r["mutating"] == (r["method"] in {"POST", "PUT", "DELETE", "PATCH"})
    assert any(r["mutating"] for r in rows)


def test_side_effect_boundaries_reference_real_gating_controls() -> None:
    report = to_report()
    known = {c["control_id"] for c in report["controls"]}
    for seb in bp0_audit.SIDE_EFFECT_BOUNDARIES:
        assert seb["id"].startswith("SEB-")
        assert seb["class"] in {
            "NONE",
            "INTERNAL_STATE",
            "SIMULATED_EXTERNAL",
            "EXTERNAL_NETWORK",
            "HOST_ENVIRONMENT",
        }
        # Every CTRL-* id named in a boundary's gating must be a real control.
        for token in str(seb["gated_by"]).replace("(", " ").replace(")", " ").split():
            if token.startswith("CTRL-"):
                cid = token.rstrip(",")
                assert cid in known, f"{seb['id']} cites unknown control {cid}"


def test_the_one_consequential_boundary_matches_the_executor_vocabulary() -> None:
    # SEB-01 is the operational tool-execution boundary; its adapters must be
    # exactly the platform's intent vocabulary (no ungoverned extra sink).
    assert set(default_tool_adapters()) == set(_INTENT_RESOURCE)


def test_disposition_is_complete_and_uses_the_agreed_vocabulary() -> None:
    for _pkg, meta in bp0_audit.MODULE_DISPOSITION.items():
        assert meta["disposition"] in {"KEEP", "HARDEN", "GAP"}
        assert meta["bp"] and meta["note"]


def test_generator_is_deterministic(tmp_path, monkeypatch) -> None:
    # Redirect output to a temp dir and generate twice; bytes must be identical.
    monkeypatch.setattr(bp0_audit, "_OUT_DIR", tmp_path)
    first = {p.name: p.read_bytes() for p in bp0_audit.generate()}
    second = {p.name: p.read_bytes() for p in bp0_audit.generate()}
    assert first == second
    # And every emitted JSON is valid + carries a schema_version.
    for name, blob in first.items():
        if name.endswith(".json"):
            doc = json.loads(blob)
            assert doc.get("schema_version") == "1.0"


def test_control_status_artifact_has_no_violations() -> None:
    # The generated control ladder must pass its own honesty invariants.
    assert to_report()["violations"] == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
