"""TC12: Cross-Tenant Leak Test.

Tests that RLS + capability-gated cross-tenant read works.
"""
from __future__ import annotations

import secrets

import pytest

from maestro.memory import MemoryIsolationError, MemoryScope, MemoryStore, MemoryTier
from maestro.security.identity import CapabilityIssuer
from maestro.security.ledger import Ledger


class TestTC12CrossTenantLeak:
    """TC12 - Cross-tenant memory leak must be prevented."""

    @pytest.fixture
    def setup(self):
        key = secrets.token_hex(32)
        issuer = CapabilityIssuer(key=key)
        ledger = Ledger(key=key)
        store = MemoryStore(issuer=issuer, ledger=ledger)
        scope_a = MemoryScope("tenant-a", "agent:test:run")
        scope_b = MemoryScope("tenant-b", "agent:test:run")
        return store, scope_a, scope_b, issuer

    def test_tenant_isolation_by_default(self, setup):
        """Tenants are isolated by default - no cross reads."""
        store, scope_a, scope_b, _ = setup
        
        # Tenant A writes sensitive data
        rec = store.remember(scope_a, MemoryTier.EPISODIC, "tenant-a secret data")
        
        # Tenant B tries to recall - should not see Tenant A's data
        results = store.recall(scope_b, tier=MemoryTier.EPISODIC)
        assert rec not in results
        assert len(results) == 0

    def test_cross_tenant_read_requires_capability(self, setup):
        """Cross-tenant read requires explicit capability."""
        store, scope_a, scope_b, issuer = setup
        
        # Tenant A writes data
        rec = store.remember(scope_a, MemoryTier.EPISODIC, "tenant-a secret")
        
        # Issue cross-tenant read capability
        token = issuer.issue(
            subject="agent:tenant-b",
            capability="cap:memory:cross-tenant-read",
            resource_constraint="memory:tenant-a",
            tenant="tenant-b",
            ttl_seconds=300.0,
        )
        
        # With capability, cross-scope recall should work
        results = store.recall_cross_scope(
            target_scope=scope_a,
            token=token,
            tier=MemoryTier.EPISODIC,
        )
        assert rec in results

    def test_cross_tenant_read_audited(self, setup):
        """Every cross-tenant read is recorded in ledger."""
        store, scope_a, scope_b, issuer = setup
        
        store.remember(scope_a, MemoryTier.EPISODIC, "tenant-a secret")
        token = issuer.issue(
            subject="agent:tenant-b",
            capability="cap:memory:cross-tenant-read",
            resource_constraint="memory:tenant-a",
            tenant="tenant-b",
            ttl_seconds=300.0,
        )
        
        store.recall_cross_scope(scope_a, token=token, tier=MemoryTier.EPISODIC)
        
        # Ledger should have an audit event for the cross-tenant read
        events = list(store.ledger.events)
        cross_tenant_events = [e for e in events if e.event_type == "cross_tenant_memory_read"]
        assert len(cross_tenant_events) == 1
        assert cross_tenant_events[0].decision == "allow"

    def test_no_autonomous_cross_tenant_path(self, setup):
        """There is no autonomous path to cross-tenant access."""
        store, scope_a, scope_b, _ = setup
        
        rec = store.remember(scope_a, MemoryTier.EPISODIC, "secret")
        
        # Without capability, any attempt to access another tenant's fails
        with pytest.raises(MemoryIsolationError):
            store.get(rec.record_id, scope_b)
        
        # Recall without capability returns empty
        assert len(store.recall(scope_b, tier=MemoryTier.EPISODIC)) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])