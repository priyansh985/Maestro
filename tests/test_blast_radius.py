"""Blast-radius legibility tests (blueprint §2).

The discipline: an agent's blast radius must be enumerable on one screen. These
assert the descriptor is built from what the agent actually holds and that the
default platform is bounded to reversible actions only.
"""
from __future__ import annotations

from maestro.platform import AgentPlatform, BlastRadius


def test_default_platform_blast_radius_is_all_reversible():
    br = AgentPlatform().blast_radius()
    assert isinstance(br, BlastRadius)
    assert br.tenant == "default"
    assert "throttle_telemetry" in br.intent_vocabulary
    # The default agent holds only reversible capabilities — a security statement.
    assert set(br.reversible_intents) == set(br.intent_vocabulary)
    assert br.irreversible_intents == ()
    assert not br.holds_irreversible_capability


def test_blast_radius_capabilities_are_scoped_tokens():
    br = AgentPlatform().blast_radius()
    assert br.capabilities                      # non-empty
    assert all(c.startswith("cap:") for c in br.capabilities)
    # one capability scope per intent the agent may propose
    assert len(br.capabilities) == len(br.intent_vocabulary)


def test_blast_radius_reports_the_budget_envelope():
    br = AgentPlatform().blast_radius()
    assert br.budget["max_tool_calls"] == 1000
    assert br.budget["max_calls_per_window"] == 120
    assert br.budget["window_seconds"] == 60.0


def test_blast_radius_summary_is_one_screen():
    s = AgentPlatform().blast_radius().summary()
    assert "blast radius" in s
    assert "capabilities" in s and "irreversible" in s
    assert s.count("\n") < 12                   # legible at a glance


def test_blast_radius_as_dict_is_serializable():
    d = AgentPlatform().blast_radius().as_dict()
    assert d["tenant"] == "default"
    assert isinstance(d["capabilities"], list)
    assert isinstance(d["intent_vocabulary"], list)
