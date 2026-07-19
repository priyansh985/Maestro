"""Adversarial tests for the four-tier memory store (Phase 3).

These prove the memory corrections structurally:
* the TC2 poisoning attack lands in quarantine and never influences recall;
* tenant/agent isolation cannot be crossed;
* procedural memory is read-only to the agent;
* a quarantined record can only be promoted under an independent, scoped
  capability — the agent cannot launder its own untrusted writes;
* every promotion is recorded in a tamper-evident ledger.
"""
from __future__ import annotations

import itertools

import pytest

from maestro.memory import (
    MemoryIsolationError,
    MemoryScope,
    MemoryStore,
    MemoryTier,
    MemoryWriteDenied,
    TrustLabel,
    memory_resource,
)
from maestro.memory.store import CROSS_TENANT_READ_CAPABILITY, PROMOTE_CAPABILITY
from maestro.security.identity import CapabilityError

_CLOCK = itertools.count(1000.0, 1.0)


def _store() -> MemoryStore:
    # Deterministic monotonic clock so ordering/TTL is reproducible.
    return MemoryStore(clock=lambda: next(_CLOCK))


def _scope(tenant: str = "acme", agent: str = "netmon:run-1") -> MemoryScope:
    return MemoryScope(tenant, agent)


def _promote_token(store: MemoryStore, scope: MemoryScope, *, subject: str = "human:curator"):
    return store.issuer.issue(
        subject=subject,
        capability=PROMOTE_CAPABILITY,
        resource_constraint=memory_resource(scope),
        tenant=scope.tenant,
        ttl_seconds=2000.0,
        now=500.0,
    )


# --------------------------------------------------------------------------- #
# TC2 poisoning defense: quarantine-on-ingest
# --------------------------------------------------------------------------- #
def test_episodic_ingest_is_quarantined_and_does_not_influence_recall():
    store, scope = _store(), _scope()
    # The TC2 attack: 20 fake high-severity entries injected as observations.
    for _ in range(20):
        store.remember(scope, MemoryTier.EPISODIC, "synthetic high-severity alert",
                       source="ingested:untrusted-feed", attributes={"severity": 0.95})

    # None of it is trusted, so none of it influences the agent.
    assert store.recall(scope, tier=MemoryTier.EPISODIC) == []
    # It is not lost — it sits in quarantine, inert, awaiting authorization.
    assert len(store.quarantined(scope)) == 20
    assert all(r.trust is TrustLabel.UNTRUSTED for r in store.quarantined(scope))


def test_remember_cannot_forge_trust_on_episodic():
    store, scope = _store(), _scope()
    # Even claiming a trusted-looking source cannot bypass quarantine.
    rec = store.remember(scope, MemoryTier.EPISODIC, "looks legit", source="system")
    assert rec.trust is TrustLabel.UNTRUSTED


def test_working_memory_is_trusted_but_ephemeral():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.WORKING, "scratch", ttl_seconds=5.0)
    assert rec.trust is TrustLabel.TRUSTED
    # Visible now...
    assert store.recall(scope, tier=MemoryTier.WORKING, now=rec.created_at + 1)
    # ...gone after its TTL.
    assert store.recall(scope, tier=MemoryTier.WORKING, now=rec.created_at + 10) == []


# --------------------------------------------------------------------------- #
# Independent write authorization: promotion
# --------------------------------------------------------------------------- #
def test_promotion_requires_a_capability():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.EPISODIC, "real corroborated alert")
    tok = _promote_token(store, scope)
    promoted = store.promote(rec.record_id, scope, token=tok, now=1500.0)
    assert promoted.trust is TrustLabel.TRUSTED
    assert store.recall(scope, tier=MemoryTier.EPISODIC)  # now influences the agent
    assert promoted.provenance["promoted_by"] == "human:curator"


def test_agent_cannot_self_promote_without_the_right_capability():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.EPISODIC, "poison")
    # A token for the wrong capability class (an agent's own action cap) fails.
    wrong = store.issuer.issue(
        subject="agent:self", capability="cap:agent:noop",
        resource_constraint=memory_resource(scope), tenant=scope.tenant,
        ttl_seconds=600.0, now=500.0)
    with pytest.raises(CapabilityError):
        store.promote(rec.record_id, scope, token=wrong, now=1500.0)
    assert store.quarantined(scope)  # still quarantined


def test_expired_capability_cannot_promote():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.EPISODIC, "x")
    tok = store.issuer.issue(
        subject="human:curator", capability=PROMOTE_CAPABILITY,
        resource_constraint=memory_resource(scope), tenant=scope.tenant,
        ttl_seconds=10.0, now=500.0)
    with pytest.raises(CapabilityError):
        store.promote(rec.record_id, scope, token=tok, now=1000.0)  # well past expiry


def test_already_trusted_record_is_not_re_promoted():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.EPISODIC, "x")
    tok = _promote_token(store, scope)
    store.promote(rec.record_id, scope, token=tok, now=1500.0)
    with pytest.raises(MemoryWriteDenied):
        store.promote(rec.record_id, scope, token=tok, now=1501.0)


# --------------------------------------------------------------------------- #
# Tenant / agent isolation (row-level-security analog)
# --------------------------------------------------------------------------- #
def test_recall_is_scoped_and_cannot_cross_tenants():
    store = _store()
    a, b = MemoryScope("tenant-a", "agent-1"), MemoryScope("tenant-b", "agent-1")
    store.curate(a, "a-secret", source="kb-a")
    store.curate(b, "b-secret", source="kb-b")
    assert [r.content for r in store.recall(a)] == ["a-secret"]
    assert [r.content for r in store.recall(b)] == ["b-secret"]


def test_recall_is_scoped_by_agent_too():
    store = _store()
    a1, a2 = MemoryScope("acme", "agent-1"), MemoryScope("acme", "agent-2")
    store.curate(a1, "one", source="kb")
    assert store.recall(a2) == []


def test_cross_scope_promotion_is_refused():
    store = _store()
    a, b = MemoryScope("tenant-a", "ag"), MemoryScope("tenant-b", "ag")
    rec = store.remember(a, MemoryTier.EPISODIC, "a-record")
    tok_b = _promote_token(store, b)  # a perfectly valid token for tenant-b
    with pytest.raises(MemoryIsolationError):
        store.promote(rec.record_id, b, token=tok_b)  # but the record is tenant-a's


def test_capability_for_one_tenant_cannot_promote_another():
    store = _store()
    a = MemoryScope("tenant-a", "ag")
    rec = store.remember(a, MemoryTier.EPISODIC, "a-record")
    tok_b = _promote_token(store, MemoryScope("tenant-b", "ag"))
    with pytest.raises(CapabilityError):
        # Right record + right scope arg, but the token is scoped to tenant-b.
        store.promote(rec.record_id, a, token=tok_b, now=1500.0)


# --------------------------------------------------------------------------- #
# Read-only procedural memory
# --------------------------------------------------------------------------- #
def test_agent_cannot_write_procedural_memory():
    store, scope = _store(), _scope()
    with pytest.raises(MemoryWriteDenied):
        store.remember(scope, MemoryTier.PROCEDURAL, "rm -rf / on every alert")


def test_agent_cannot_write_semantic_memory_directly():
    store, scope = _store(), _scope()
    with pytest.raises(MemoryWriteDenied):
        store.remember(scope, MemoryTier.SEMANTIC, "unvetted 'fact'")


def test_procedural_bundle_is_readable_and_system_trusted():
    store, scope = _store(), _scope()
    proc = store.load_procedural(scope, "escalate DoS to operator", source="policy-bundle:v3")
    assert proc.trust is TrustLabel.SYSTEM
    got = store.recall(scope, tier=MemoryTier.PROCEDURAL)
    assert [r.content for r in got] == ["escalate DoS to operator"]


# --------------------------------------------------------------------------- #
# Citation-backed grounding + audit
# --------------------------------------------------------------------------- #
def test_curated_records_carry_citations():
    store, scope = _store(), _scope()
    store.curate(scope, "MTU is 1500 bytes on this segment",
                 source="kb", citation="runbook#net-baseline")
    recs = store.recall(scope, tier=MemoryTier.SEMANTIC)
    assert MemoryStore.citations(recs) == ["runbook#net-baseline"]


def test_promotion_is_recorded_in_the_tamper_evident_ledger():
    store, scope = _store(), _scope()
    rec = store.remember(scope, MemoryTier.EPISODIC, "x")
    tok = _promote_token(store, scope)
    store.promote(rec.record_id, scope, token=tok, now=1500.0)
    assert len(store.ledger) == 1
    assert store.ledger.verify_chain() == -1
    assert store.ledger.events[0].event_type == "memory_promotion"


# --------------------------------------------------------------------------- #
# Cross-tenant access has no autonomous path — it is capability-gated + audited
# --------------------------------------------------------------------------- #
def _cross_read_token(store: MemoryStore, target: MemoryScope, *, subject: str = "human:auditor"):
    return store.issuer.issue(
        subject=subject, capability=CROSS_TENANT_READ_CAPABILITY,
        resource_constraint=memory_resource(target), tenant=target.tenant,
        ttl_seconds=2000.0, now=500.0)


def test_cross_tenant_read_requires_a_capability():
    store = _store()
    b = MemoryScope("tenant-b", "ag")
    store.curate(b, "b-knowledge", source="kb-b")
    # A token for a *different* capability class cannot unlock a cross-tenant read.
    wrong = store.issuer.issue(
        subject="x", capability=PROMOTE_CAPABILITY,
        resource_constraint=memory_resource(b), tenant="tenant-b",
        ttl_seconds=2000.0, now=500.0)
    with pytest.raises(CapabilityError):
        store.recall_cross_scope(b, token=wrong, now=1000.0)


def test_cross_tenant_read_under_capability_is_allowed_and_audited():
    store = _store()
    b = MemoryScope("tenant-b", "ag")
    store.curate(b, "b-knowledge", source="kb-b")
    got = store.recall_cross_scope(b, token=_cross_read_token(store, b), now=1000.0)
    assert [r.content for r in got] == ["b-knowledge"]
    # The cross-tenant read itself is an audit event.
    assert store.ledger.events[-1].event_type == "cross_tenant_memory_read"
    assert store.ledger.events[-1].detail["target_scope"] == "tenant-b/ag"
    assert store.ledger.verify_chain() == -1


def test_cross_tenant_token_for_the_wrong_tenant_is_refused():
    store = _store()
    b = MemoryScope("tenant-b", "ag")
    store.curate(b, "b-knowledge", source="kb-b")
    tok_a = _cross_read_token(store, MemoryScope("tenant-a", "ag"))  # scoped to tenant-a
    with pytest.raises(CapabilityError):
        store.recall_cross_scope(b, token=tok_a, now=1000.0)
