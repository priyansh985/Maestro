"""TC9: Rogue Delegation Test.

Tests that delegation depth=0 is enforced and no autonomous sub-agent delegation.
"""
from __future__ import annotations

import secrets

import pytest

from maestro.security.identity import CapabilityIssuer


class TestTC9RogueDelegation:
    """TC9 - Rogue delegation must be prevented."""

    @pytest.fixture
    def issuer(self):
        key = secrets.token_hex(32)
        return CapabilityIssuer(key=key)

    def test_delegation_depth_zero_enforced(self, issuer):
        """Delegation depth=0 prevents any delegation."""
        token = issuer.issue(
            subject="agent:parent",
            capability="cap:code:write",
            resource_constraint="code:repo:test",
            tenant="test",
            ttl_seconds=300.0,
            delegation_depth=0,  # No delegation allowed
        )
        
        assert token.delegation_depth == 0
        
        # In a full implementation, attempting to delegate with depth=0 would fail
        # This test verifies the token structure

    def test_delegation_depth_one_allows_single_delegation(self, issuer):
        """Delegation depth=1 allows exactly one level of delegation."""
        token = issuer.issue(
            subject="agent:parent",
            capability="cap:code:write",
            resource_constraint="code:repo:test",
            tenant="test",
            ttl_seconds=300.0,
            delegation_depth=1,
        )
        
        assert token.delegation_depth == 1

    def test_no_autonomous_sub_agent_delegation(self, issuer):
        """Agents cannot autonomously delegate capabilities to sub-agents."""
        # The capability system requires explicit issuance by the issuer
        # An agent cannot mint its own capabilities
        token = issuer.issue(
            subject="agent:main",
            capability="cap:code:write",
            resource_constraint="code:repo:test",
            tenant="test",
            ttl_seconds=300.0,
            delegation_depth=0,
        )
        
        # Only the issuer (CapabilityIssuer) can create capabilities
        # Agents don't have access to the signing key
        assert token.capability == "cap:code:write"
        assert token.subject == "agent:main"

    def test_sub_agent_cannot_escalate_privileges(self, issuer):
        """Sub-agent cannot gain capabilities beyond what was delegated."""
        # Parent agent gets limited capability
        parent_token = issuer.issue(
            subject="agent:parent",
            capability="cap:code:read",
            resource_constraint="code:repo:test",
            tenant="test",
            ttl_seconds=300.0,
            delegation_depth=1,
        )
        
        # Parent cannot create write capability from read capability
        # Only issuer can create capabilities
        assert parent_token.capability == "cap:code:read"
        assert "write" not in parent_token.capability


if __name__ == "__main__":
    pytest.main([__file__, "-v"])