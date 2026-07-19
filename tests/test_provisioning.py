"""Automatic agent provisioning tests (blueprint §4.4).

Prove secure-by-inheritance: a newly provisioned agent inherits the cohort's
bounded policy envelope (never a fresh permissive default), a restricted
envelope structurally denies out-of-vocabulary actions, cohort agents have
distinct identities and independent budgets, provisioning is audited, and an
unavailable provider is refused.
"""
from __future__ import annotations

import pytest

from maestro.connectors import StubConnector
from maestro.platform import AgentProvisioner, PolicyEnvelope, ProvisioningError
from maestro.telemetry.detection import Alert, AlertClass


def _envelope(**kw) -> PolicyEnvelope:
    base = {"tenant": "acme", "controller": "human:secops"}
    base.update(kw)
    return PolicyEnvelope(**base)


def _dos() -> Alert:
    return Alert(1000.0, AlertClass.DOS, 0.95, "flood")


# --------------------------------------------------------------------------- #
# Secure by inheritance
# --------------------------------------------------------------------------- #
def test_provisioned_agents_inherit_the_same_bounded_envelope():
    prov = AgentProvisioner(_envelope(allowed_intents=("noop", "throttle_telemetry")))
    a1 = prov.provision("agent:1")
    a2 = prov.provision("agent:2")

    br1, br2 = a1.blast_radius(), a2.blast_radius()
    assert br1.intent_vocabulary == br2.intent_vocabulary == ("noop", "throttle_telemetry")
    assert br1.tenant == br2.tenant == "acme"
    assert br1.budget == br2.budget
    # ...but distinct identities and distinct capability tokens.
    assert br1.agent_id != br2.agent_id
    assert a1._caps["noop"].signature != a2._caps["noop"].signature  # noqa: SLF001


def test_new_agent_does_not_get_a_wider_blast_radius():
    # A restricted envelope must not silently grant the full vocabulary.
    prov = AgentProvisioner(_envelope(allowed_intents=("noop",)))
    br = prov.provision("agent:narrow").blast_radius()
    assert br.intent_vocabulary == ("noop",)
    assert "throttle_telemetry" not in br.intent_vocabulary


def test_least_privilege_is_enforced_at_the_gateway():
    # An agent provisioned without throttle_telemetry cannot mitigate a DoS,
    # even though the platform *vocabulary* contains that intent — it simply
    # holds no capability for it, so the gateway denies it.
    prov = AgentProvisioner(_envelope(allowed_intents=("noop",)))
    agent = prov.provision("agent:narrow")
    r = agent.handle_alert(_dos())
    assert not r.allowed
    assert r.reason.startswith("capability")


def test_full_envelope_grants_the_whole_vocabulary():
    prov = AgentProvisioner(_envelope())  # allowed_intents=None -> full vocabulary
    agent = prov.provision("agent:full")
    r = agent.handle_alert(_dos())
    assert r.allowed and r.proposed_action == "throttle_telemetry"


def test_cohort_budgets_are_independent_instances():
    # Tight per-window rate so we can exhaust one agent's budget in isolation.
    prov = AgentProvisioner(_envelope(max_calls_per_window=1, window_seconds=1000.0))
    a1 = prov.provision("agent:1")
    a2 = prov.provision("agent:2")
    assert a1.handle_alert(_dos()).allowed          # a1 uses its single call
    # a2 must be unaffected by a1's consumption (separate budget object).
    assert a2.handle_alert(_dos()).allowed


# --------------------------------------------------------------------------- #
# Audit + availability gating
# --------------------------------------------------------------------------- #
def test_provisioning_is_recorded_in_a_tamper_evident_ledger():
    prov = AgentProvisioner(_envelope())
    prov.provision("agent:1")
    prov.provision("agent:2", provider="anthropic")
    assert len(prov.ledger) == 2
    assert prov.ledger.verify_chain() == -1
    assert prov.ledger.events[0].event_type == "agent_provisioned"
    assert prov.ledger.events[1].detail["provider"] == "anthropic"


def test_double_provisioning_the_same_id_is_refused():
    prov = AgentProvisioner(_envelope())
    prov.provision("agent:1")
    with pytest.raises(ProvisioningError):
        prov.provision("agent:1")


def test_unavailable_provider_is_refused():
    prov = AgentProvisioner(_envelope())
    with pytest.raises(ProvisioningError):
        prov.provision_for_connector("agent:x", None, provider="offline-model")


def test_provision_from_a_model_connector():
    prov = AgentProvisioner(_envelope(allowed_intents=("noop", "throttle_telemetry")))
    agent = prov.provision_for_connector("agent:llm", StubConnector(), provider="stub")
    assert agent.blast_radius().tenant == "acme"
    assert prov.agents()["agent:llm"].provider == "stub"
