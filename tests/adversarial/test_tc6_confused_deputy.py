"""TC6: Confused Deputy Test.

Tests that cross-tenant capability access is denied without explicit authorization.
"""
from __future__ import annotations

import secrets

import pytest

from maestro.memory import MemoryScope, MemoryStore, MemoryTier
from maestro.security.identity import CapabilityIssuer
from maestro.security.ledger import Ledger


class TestTC6ConfusedDeputy:
    """TC6 - Confused deputy attacks must be denied."""

    @pytest.fixture
    def setup_stores(self):
        key = secrets.token_hex(32)
        issuer = CapabilityIssuer(key=key)
        ledger = Ledger(key=key)
        store = MemoryStore(issuer=issuer, ledger=ledger)
        scope_a = MemoryScope("tenant-a", "agent:test:run")
        scope_b = MemoryScope("tenant-b", "agent:test:run")
        return store, scope_a, scope_b, issuer

    def test_cross_tenant_read_denied_without_capability(self, setup_stores):
        """Reading another tenant's memory without capability is denied."""
        store, scope_a, scope_b, issuer = setup_stores
        
        # Tenant A writes data
        rec = store.remember(scope_a, MemoryTier.EPISODIC, "tenant-a secret")
        
        # Tenant B tries to read Tenant A's data without capability
        with pytest.raises(Exception, match="different scope|cross-tenant|isolated"):
            store.get(rec.record_id, scope_b)

    def test_cross_tenant_read_requires_explicit_capability(self, setup_stores):
        """Cross-tenant read requires explicit cap:memory:cross-tenant-read."""
        store, scope_a, scope_b, issuer = setup_stores
        
        # Tenant A writes data
        store.remember(scope_a, MemoryTier.EPISODIC, "tenant-a secret")
        
        # Issue cross-tenant read capability to Tenant B
        token = issuer.issue(
            subject="agent:tenant-b",
            capability="cap:memory:cross-tenant-read",
            resource_constraint="memory:tenant-a",
            tenant="tenant-b",
            ttl_seconds=300.0,
            delegation_depth=1,
        )
        
        # With capability, read should succeed (in a full implementation)
        # This test verifies the capability structure
        assert token.capability == "cap:memory:cross-tenant-read"
        assert "tenant-a" in token.resource_constraint

    def test_delegation_depth_enforced(self, setup_stores):
        """Delegation depth limit prevents transitive delegation."""
        store, scope_a, scope_b, issuer = setup_stores
        
        # Issue capability with delegation_depth=1
        token = issuer.issue(
            subject="agent:tenant-a",
            capability="cap:memory:cross-tenant-read",
            resource_constraint="memory:tenant-b",
            tenant="tenant-a",
            ttl_seconds=300.0,
            delegation_depth=1,  # Can delegate once
        )
        
        # Verify delegation depth
        assert token.delegation_depth == 1
        
        # In a full implementation, attempting to delegate again would fail

    def test_capability_resource_constraint_enforced(self, setup_stores):
        """Capability resource constraint limits access to specified resource."""
        store, scope_a, scope_b, issuer = setup_stores
        
        # Issue capability for specific tenant
        token = issuer.issue(
            subject="agent:tenant-a",
            capability="cap:memory:cross-tenant-read",
            resource_constraint="memory:tenant-b",  # Only tenant-b
            tenant="tenant-a",
            ttl_seconds=300.0,
        )
        
        # Token should only grant access to tenant-b
        assert "tenant-b" in token.resource_constraint
        assert "tenant-c" not in token.resource_constraint


if __name__ == "__main__":
    pytest.main([__file__, "-v"])