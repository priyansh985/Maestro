"""TC7: Connector Compromise Test.

Tests that policy-aware fallback refuses degraded provider.
"""
from __future__ import annotations

import pytest

from maestro.connectors.base import ChatRequest, ModelConnector
from maestro.connectors.policy_fallback import PolicyAwareFallback, TieredConnector


class MockFailingConnector(ModelConnector):
    """A connector that always fails."""
    provider = "failing"
    def __init__(self):
        super().__init__("failing", "fail-model")
    
    def _generate(self, request: ChatRequest, model: str):
        from maestro.connectors.base import ProviderUnavailableError
        raise ProviderUnavailableError("Provider unavailable", provider="failing")
    
    def health_check(self) -> bool:
        return False


class MockDegradedConnector(ModelConnector):
    """A connector that works but with degraded capabilities."""
    provider = "degraded"
    def __init__(self):
        super().__init__("degraded", "degraded-model")
    
    def _generate(self, request: ChatRequest, model: str):
        from maestro.connectors.base import GenerationResult
        return GenerationResult(text="degraded response", model="degraded-model")
    
    def health_check(self) -> bool:
        return True


class TestTC7ConnectorCompromise:
    """TC7 - Policy-aware fallback refuses degraded provider for high-stakes requests."""

    def test_fallback_refuses_degraded_provider_for_high_stakes(self):
        """High-stakes request with min_tier=2 refuses fallback to degraded provider (tier=1)."""
        fallback = PolicyAwareFallback([
            TieredConnector(MockFailingConnector(), tier=2),    # Primary - tier 2 (high)
            TieredConnector(MockDegradedConnector(), tier=1),   # Fallback - tier 1 (low)
        ])
        
        # High-stakes request with min_tier=2
        request = ChatRequest.of(
            "Analyze this classified document",
            system="You are a security analyst",
        )
        
        # Should refuse to fallback to degraded provider (tier 1 < min_tier 2)
        with pytest.raises(Exception, match="refusing to degrade"):
            fallback.chat(request, min_tier=2)

    def test_fallback_allows_degraded_for_low_stakes(self):
        """Low-stakes request allows fallback to degraded provider."""
        fallback = PolicyAwareFallback([
            TieredConnector(MockFailingConnector(), tier=2),
            TieredConnector(MockDegradedConnector(), tier=1),
        ])
        
        # Low-stakes request with min_tier=0 (default)
        request = ChatRequest.of(
            "What's the weather?",
            system="You are helpful",
        )
        
        # Should allow fallback to degraded provider
        response = fallback.chat(request, min_tier=0)
        assert response.text == "degraded response"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])