"""Enforcement Plane tests: typed proposals, capabilities, ledger, and the PEP.

These are deliberately adversarial (the ``VerificationLevel.ADVERSARIAL`` bar in
the truth audit): each control is attacked at its boundary — forged/expired/
out-of-scope capabilities, ghost evidence, tampered ledger links, missing
tokens on capability-required actions, and direct high-risk execution.
"""
from __future__ import annotations

import dataclasses

import pytest

from maestro.security.action import (
    ActionProposal,
    InvalidProposal,
    parse_proposal,
)
from maestro.security.enforcement import PolicyEnforcementPoint
from maestro.security.identity import (
    MAX_DELEGATION_DEPTH,
    CapabilityError,
    CapabilityIssuer,
)
from maestro.security.ledger import Ledger
from maestro.security.risk_engine import Decision, RiskInputs

KEY = "k" * 32
TENANT = "tenant-a"


def _risk(level: float, uncertainty: float = 0.0) -> RiskInputs:
    return RiskInputs(level, level, level, level, level, level, level, uncertainty)


def _issuer() -> CapabilityIssuer:
    return CapabilityIssuer(key=KEY)


def _token_for(issuer: CapabilityIssuer, proposal: ActionProposal, **kw):
    return issuer.issue(
        subject="agent:run1",
        capability=proposal.capability,
        resource_constraint=proposal.resource,
        tenant=TENANT,
        ttl_seconds=kw.pop("ttl_seconds", 900),
        **kw,
    )


def _proposal(intent: str = "read_flow_summary", target: str = "10.0.0.0/8") -> ActionProposal:
    return parse_proposal({
        "intent": intent, "target": target, "reason": "test",
        "evidence_ids": ["alert:1"], "requested_ttl_seconds": 900,
    })


# --------------------------------------------------------------------------- #
# Capability tokens
# --------------------------------------------------------------------------- #
def test_capability_issue_and_verify_roundtrip():
    iss = _issuer()
    t = iss.issue("agent:run1", "cap:firewall:block-ip", "203.0.113.0/24", TENANT, 900)
    iss.verify(t, capability="cap:firewall:block-ip",
               resource_constraint="203.0.113.0/24", tenant=TENANT)  # no raise


@pytest.mark.parametrize("field,value", [
    ("capability", "cap:firewall:rate-limit"),
    ("resource_constraint", "10.0.0.0/8"),
    ("tenant", "tenant-b"),
])
def test_capability_scope_mismatch_rejected(field, value):
    iss = _issuer()
    t = iss.issue("agent:run1", "cap:firewall:block-ip", "203.0.113.0/24", TENANT, 900)
    kwargs = {"capability": "cap:firewall:block-ip",
              "resource_constraint": "203.0.113.0/24", "tenant": TENANT}
    kwargs[field] = value
    with pytest.raises(CapabilityError):
        iss.verify(t, **kwargs)


def test_capability_expiry():
    iss = _issuer()
    t = iss.issue("agent:run1", "cap:x", "r", TENANT, 10, now=1000.0)
    with pytest.raises(CapabilityError):
        iss.verify(t, capability="cap:x", resource_constraint="r", tenant=TENANT, now=1011.0)


def test_forged_capability_rejected():
    iss = _issuer()
    t = iss.issue("agent:run1", "cap:x", "r", TENANT, 900)
    forged = dataclasses.replace(t, capability="cap:admin")  # signature no longer matches
    with pytest.raises(CapabilityError):
        iss.verify(forged, capability="cap:admin", resource_constraint="r", tenant=TENANT)


def test_capability_verified_with_wrong_key_fails():
    good = _issuer().issue("agent:run1", "cap:x", "r", TENANT, 900)
    with pytest.raises(CapabilityError):
        CapabilityIssuer(key="different-key").verify(
            good, capability="cap:x", resource_constraint="r", tenant=TENANT)


def test_delegation_narrows_and_caps_depth():
    iss = _issuer()
    parent = iss.issue("agent:run1", "cap:x", "r", TENANT, 900, now=1000.0)
    child = iss.delegate(parent, "agent:sub1", now=1000.0)
    assert child.delegation_depth == 1
    assert child.expires_at <= parent.expires_at  # cannot outlive parent
    iss.verify(child, capability="cap:x", resource_constraint="r", tenant=TENANT, now=1001.0)


def test_delegation_depth_cap():
    iss = _issuer()
    with pytest.raises(CapabilityError):
        iss.issue("a", "cap:x", "r", TENANT, 900, delegation_depth=MAX_DELEGATION_DEPTH + 1)


def test_issuer_requires_key(monkeypatch):
    monkeypatch.delenv("MAESTRO_SIGNING_KEY", raising=False)
    with pytest.raises(CapabilityError):
        CapabilityIssuer()


# --------------------------------------------------------------------------- #
# Typed action schema
# --------------------------------------------------------------------------- #
def test_parse_valid_proposal():
    p = _proposal("block_source_ip", "203.0.113.0/24")
    assert p.action_class == "irreversible_network_change"
    assert p.capability == "cap:firewall:block-ip"
    assert p.requires_capability()


@pytest.mark.parametrize("bad", [
    {"target": "x", "reason": "r", "evidence_ids": ["e"], "requested_ttl_seconds": 1},  # no intent
    {"intent": "read_flow_summary", "reason": "r", "evidence_ids": ["e"],
     "requested_ttl_seconds": 1},  # no target
    {"intent": "read_flow_summary", "target": "x", "reason": "r",
     "evidence_ids": "e", "requested_ttl_seconds": 1},  # evidence not a list
    {"intent": "read_flow_summary", "target": "x", "reason": "r",
     "evidence_ids": ["e"], "requested_ttl_seconds": True},  # bool ttl
    {"intent": "read_flow_summary", "target": "x", "reason": "r",
     "evidence_ids": ["e"], "requested_ttl_seconds": 0},  # non-positive ttl
    {"intent": "hack_the_planet", "target": "x", "reason": "r",
     "evidence_ids": ["e"], "requested_ttl_seconds": 1},  # unknown intent
    {"intent": "read_flow_summary", "target": "", "reason": "r",
     "evidence_ids": ["e"], "requested_ttl_seconds": 1},  # empty target
])
def test_parse_rejects_bad_proposals(bad):
    with pytest.raises(InvalidProposal):
        parse_proposal(bad)


def test_parse_json_string_and_bad_json():
    p = parse_proposal('{"intent":"read_flow_summary","target":"x","reason":"r",'
                       '"evidence_ids":["e"],"requested_ttl_seconds":1}')
    assert p.intent == "read_flow_summary"
    with pytest.raises(InvalidProposal):
        parse_proposal("{not json")


def test_content_hash_is_deterministic():
    assert _proposal().content_hash() == _proposal().content_hash()


# --------------------------------------------------------------------------- #
# Tamper-evident ledger
# --------------------------------------------------------------------------- #
def test_ledger_chain_intact():
    led = Ledger(key=KEY)
    for i in range(3):
        led.append(event_type="e", actor_identity="a", decision="allow", input_hash=f"h{i}")
    assert led.verify_chain() == -1
    assert len(led) == 3


def test_ledger_detects_tampering():
    led = Ledger(key=KEY)
    for i in range(3):
        led.append(event_type="e", actor_identity="a", decision="allow", input_hash=f"h{i}")
    # Mutate a committed event's payload but keep its stored hash/hmac.
    led._events[1] = dataclasses.replace(led._events[1], decision="DENY")
    assert led.verify_chain() == 1


def test_ledger_file_roundtrip_and_file_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = Ledger(path, key=KEY)
    led.append(event_type="e", actor_identity="a", decision="allow", input_hash="h0")
    led.append(event_type="e", actor_identity="a", decision="allow", input_hash="h1")
    assert Ledger(path, key=KEY).verify_chain() == -1  # reload intact
    # Corrupt a line on disk.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"h0"', '"HACKED"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert Ledger(path, key=KEY).verify_chain() == 0


# --------------------------------------------------------------------------- #
# Policy Enforcement Point
# --------------------------------------------------------------------------- #
def _pep(**kw) -> tuple[PolicyEnforcementPoint, Ledger]:
    led = Ledger(key=KEY)
    adapters = {
        "read_flow_summary": lambda p: {"ok": True, "summary": "x"},
        "block_source_ip": lambda p: {"ok": True, "blocked": p.target},
        "run_containment_script": lambda p: {"ok": True},
    }
    adapters.update(kw.pop("adapters", {}))
    pep = PolicyEnforcementPoint(
        issuer=_issuer(), ledger=led,
        evidence_exists=lambda e: e in {"alert:1", "flow:1"},
        tenant=TENANT, adapters=adapters, approver=kw.pop("approver", None),
    )
    return pep, led


def test_pep_allows_low_risk_read_without_token():
    pep, led = _pep()
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="agent:run1")
    assert res.allowed and res.decision == Decision.ALLOW
    assert res.output["summary"] == "x"
    assert led.verify_chain() == -1 and len(led) == 1


def test_pep_denies_capability_required_action_without_token():
    pep, led = _pep()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    res = pep.authorize_and_execute(p, token=None, risk=_risk(1.0), actor="agent:run1")
    assert not res.allowed and res.reason.startswith("capability")


def test_pep_allows_capability_required_with_valid_token():
    pep, led = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    res = pep.authorize_and_execute(p, token=_token_for(iss, p), risk=_risk(1.0), actor="a")
    assert res.allowed and res.output["blocked"] == "203.0.113.0/24"


def test_pep_denies_missing_evidence():
    pep, _ = _pep()
    p = parse_proposal({"intent": "read_flow_summary", "target": "x", "reason": "r",
                        "evidence_ids": ["ghost:99"], "requested_ttl_seconds": 1})
    res = pep.authorize_and_execute(p, token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("evidence")


def test_pep_hard_denies_high_risk():
    pep, _ = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    res = pep.authorize_and_execute(p, token=_token_for(iss, p), risk=_risk(4.0), actor="a")
    assert not res.allowed and res.decision == Decision.DENY_AUTONOMOUS


def test_pep_emergency_containment_denies():
    pep, _ = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    res = pep.authorize_and_execute(p, token=_token_for(iss, p), risk=_risk(5.0), actor="a")
    assert not res.allowed and res.decision == Decision.EMERGENCY_CONTAINMENT


def test_pep_approval_gate():
    iss = _issuer()
    p = _proposal("read_flow_summary")
    tok = _token_for(iss, p)
    # all-3s -> residual 3.0 -> REQUIRE_APPROVAL
    denied, _ = _pep()
    r1 = denied.authorize_and_execute(p, token=tok, risk=_risk(3.0), actor="a")
    assert not r1.allowed and r1.reason.startswith("approval")
    approved, _ = _pep(approver=lambda pr, d, risk: True)
    r2 = approved.authorize_and_execute(p, token=tok, risk=_risk(3.0), actor="a")
    assert r2.allowed and r2.decision == Decision.REQUIRE_APPROVAL


def test_pep_unknown_adapter_denies():
    pep, _ = _pep(adapters={})
    p = _proposal("rotate_credentials", "vault:db")
    iss = _issuer()
    # remove the default adapter for this intent by using a PEP without it
    pep2 = PolicyEnforcementPoint(
        issuer=iss, ledger=Ledger(key=KEY),
        evidence_exists=lambda e: True, tenant=TENANT,
        adapters={}, approver=None)
    res = pep2.authorize_and_execute(p, token=_token_for(iss, p), risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("adapter")


def test_pep_adapter_exception_fails_closed():
    def boom(p):
        raise RuntimeError("adapter blew up")
    pep, _ = _pep(adapters={"read_flow_summary": boom})
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("execution")


def test_pep_postcondition_failure_denies():
    pep, _ = _pep(adapters={"read_flow_summary": lambda p: {"ok": False}})
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("postcondition")


def test_pep_kill_switch():
    pep, _ = _pep()
    pep.halt()
    res = pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.decision == Decision.EMERGENCY_CONTAINMENT
    pep.resume()
    assert pep.authorize_and_execute(
        _proposal(), token=None, risk=_risk(1.0), actor="a").allowed


def test_pep_submit_raw_rejects_bad_schema():
    pep, led = _pep()
    res = pep.submit_raw("{not json", token=None, risk=_risk(1.0), actor="a")
    assert not res.allowed and res.reason.startswith("schema")
    assert len(led) == 1  # denial still audited


def test_pep_every_outcome_is_audited_and_chain_intact():
    pep, led = _pep()
    iss = _issuer()
    p = _proposal("block_source_ip", "203.0.113.0/24")
    pep.authorize_and_execute(_proposal(), token=None, risk=_risk(1.0), actor="a")  # allow
    pep.authorize_and_execute(p, token=None, risk=_risk(1.0), actor="a")            # deny cap
    pep.authorize_and_execute(p, token=_token_for(iss, p), risk=_risk(5.0), actor="a")  # deny risk
    assert len(led) == 3
    assert led.verify_chain() == -1
