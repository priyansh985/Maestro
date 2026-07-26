"""Signed policy bundles + two-person change control (CTRL-L6-03).

These tests pin the governance invariants the executor relies on: a policy is a
signed, versioned artifact; a change to it requires two distinct people
(separation of duties); the active bundle's integrity is re-verified on every
read (fail-closed); and every governed change is recorded in the tamper-evident
ledger. The boundary wiring (the PEP consulting the active bundle) is proven in
``test_platform.py``; here we prove the registry itself.
"""
from __future__ import annotations

import dataclasses

import pytest

from maestro.security.ledger import Ledger
from maestro.security.policy_bundle import (
    PolicyBundle,
    PolicyChangeError,
    PolicyRegistry,
    genesis_registry,
)

KEY = "k" * 32


def _reg(ledger: Ledger | None = None, min_approvals: int = 1) -> PolicyRegistry:
    return genesis_registry(
        ["noop", "throttle_telemetry", "alert_operator"],
        key=KEY, ledger=ledger, min_approvals=min_approvals)


# --------------------------------------------------------------------------- #
# PolicyBundle — content addressing
# --------------------------------------------------------------------------- #
def test_digest_is_order_independent_and_content_bound():
    a = PolicyBundle.create(version=1, allowed_intents=["b", "a"], created_at=0.0)
    b = PolicyBundle.create(version=1, allowed_intents=["a", "b"], created_at=0.0)
    assert a.digest() == b.digest()          # order-independent
    c = PolicyBundle.create(version=1, allowed_intents=["a", "b", "c"], created_at=0.0)
    assert c.digest() != a.digest()          # content-bound


def test_permits_and_limit_accessors():
    bundle = PolicyBundle.create(
        version=1, allowed_intents=["noop"], limits={"max_tool_calls": 5.0})
    assert bundle.permits("noop") and not bundle.permits("block_source_ip")
    assert bundle.limit("max_tool_calls") == 5.0
    assert bundle.limit("missing", default=-1.0) == -1.0


# --------------------------------------------------------------------------- #
# Genesis — the deploy-time baseline
# --------------------------------------------------------------------------- #
def test_genesis_establishes_a_verified_v1_baseline():
    reg = _reg()
    active = reg.active()
    assert active.bundle.version == 1
    assert active.approvers == ()            # single-authority bootstrap
    assert active.bundle.permits("throttle_telemetry")


def test_genesis_is_not_a_ledger_event_but_a_change_is():
    led = Ledger(key=KEY)
    reg = _reg(ledger=led)
    assert len(led) == 0                     # baseline ships with the platform
    v2 = PolicyBundle.create(version=2, allowed_intents=["noop"],
                             parent_digest=reg.active().bundle.digest())
    rid = reg.propose(v2, proposer="user:alice")
    reg.approve(rid, approver="user:bob")
    assert [e.event_type for e in led.events] == ["policy.bundle.activated"]
    ev = led.events[-1]
    assert ev.detail["version"] == 2 and ev.detail["approvers"] == ["user:bob"]


def test_genesis_only_once_and_must_be_v1():
    reg = _reg()
    with pytest.raises(PolicyChangeError, match="already established"):
        reg.genesis(PolicyBundle.create(version=1, allowed_intents=["noop"]),
                    established_by="x")
    fresh = PolicyRegistry(key=KEY)
    with pytest.raises(PolicyChangeError, match="version 1"):
        fresh.genesis(PolicyBundle.create(version=2, allowed_intents=["noop"]),
                      established_by="x")


def test_no_active_bundle_fails_closed():
    fresh = PolicyRegistry(key=KEY)
    with pytest.raises(PolicyChangeError, match="no active policy"):
        fresh.active()
    with pytest.raises(PolicyChangeError):
        fresh.propose(PolicyBundle.create(version=2, allowed_intents=["noop"]),
                      proposer="user:alice")


# --------------------------------------------------------------------------- #
# Two-person change (separation of duties)
# --------------------------------------------------------------------------- #
def test_a_distinct_approver_activates_the_change():
    reg = _reg()
    v2 = PolicyBundle.create(version=2, allowed_intents=["noop", "alert_operator"],
                             parent_digest=reg.active().bundle.digest())
    rid = reg.propose(v2, proposer="user:alice")
    assert reg.approve(rid, approver="user:bob") is not None
    assert reg.active().bundle.version == 2
    assert not reg.active().bundle.permits("throttle_telemetry")
    assert reg.pending == {}                  # request consumed on activation


def test_proposer_cannot_approve_their_own_change():
    reg = _reg()
    v2 = PolicyBundle.create(version=2, allowed_intents=["noop"],
                             parent_digest=reg.active().bundle.digest())
    rid = reg.propose(v2, proposer="user:alice")
    with pytest.raises(PolicyChangeError, match="two-person rule"):
        reg.approve(rid, approver="user:alice")
    assert reg.active().bundle.version == 1    # unchanged


def test_duplicate_approval_cannot_fake_quorum():
    reg = _reg(min_approvals=2)
    v2 = PolicyBundle.create(version=2, allowed_intents=["noop"],
                             parent_digest=reg.active().bundle.digest())
    rid = reg.propose(v2, proposer="user:alice")
    assert reg.approve(rid, approver="user:bob") is None      # 1 of 2
    with pytest.raises(PolicyChangeError, match="already approved"):
        reg.approve(rid, approver="user:bob")
    assert reg.active().bundle.version == 1
    assert reg.approve(rid, approver="user:carol") is not None  # 2 of 2 distinct
    assert reg.active().bundle.version == 2


def test_unknown_change_request_is_rejected():
    reg = _reg()
    with pytest.raises(PolicyChangeError, match="unknown change request"):
        reg.approve("chg-9999", approver="user:bob")


# --------------------------------------------------------------------------- #
# Version chain integrity
# --------------------------------------------------------------------------- #
def test_proposal_must_be_next_version_and_chain_to_active():
    reg = _reg()
    digest = reg.active().bundle.digest()
    with pytest.raises(PolicyChangeError, match="active . 1"):
        reg.propose(PolicyBundle.create(version=3, allowed_intents=["noop"],
                                        parent_digest=digest), proposer="user:alice")
    with pytest.raises(PolicyChangeError, match="parent_digest mismatch"):
        reg.propose(PolicyBundle.create(version=2, allowed_intents=["noop"],
                                        parent_digest="sha256:not-the-active-one"),
                    proposer="user:alice")


def test_a_concurrent_change_goes_stale_once_the_policy_advances():
    reg = _reg()
    digest = reg.active().bundle.digest()
    a = PolicyBundle.create(version=2, allowed_intents=["noop"], parent_digest=digest)
    b = PolicyBundle.create(version=2, allowed_intents=["alert_operator"], parent_digest=digest)
    rid_a = reg.propose(a, proposer="user:alice")
    rid_b = reg.propose(b, proposer="user:carol")
    reg.approve(rid_a, approver="user:bob")          # v2 == a activates
    assert reg.active().bundle.permits("noop")
    with pytest.raises(PolicyChangeError, match="stale change"):
        reg.approve(rid_b, approver="user:dave")     # b was against v1, now stale
    assert reg.active().bundle.digest() == a.digest()


# --------------------------------------------------------------------------- #
# Tamper-evidence (fail-closed verification)
# --------------------------------------------------------------------------- #
def test_a_forged_signature_on_the_active_bundle_fails_closed():
    reg = _reg()
    reg._active = dataclasses.replace(reg._active, signature="deadbeef")
    with pytest.raises(PolicyChangeError, match="forged or tampered"):
        reg.active()


def test_mutating_the_active_bundle_content_invalidates_its_signature():
    reg = _reg()
    swapped = PolicyBundle.create(version=1, allowed_intents=["block_source_ip"],
                                  parent_digest=None)
    reg._active = dataclasses.replace(reg._active, bundle=swapped)   # keep old sig
    with pytest.raises(PolicyChangeError, match="forged or tampered"):
        reg.active()


def test_a_different_key_cannot_verify_the_active_bundle():
    reg = _reg()
    reg._key = b"a-different-key-entirely-000000000000"
    with pytest.raises(PolicyChangeError, match="forged or tampered"):
        reg.active()
