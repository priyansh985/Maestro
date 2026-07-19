"""Multi-model routing, resilience, and aggregation tests (blueprint §6).

Covers latency-aware routing, the policy-aware fallback correction (fail closed
rather than silently downgrade a high-stakes request), and Mixture-of-Agents
aggregation with disagreement as an uncertainty signal.
"""
from __future__ import annotations

import pytest

from maestro.connectors import (
    LatencyAwareRouter,
    LatencyTracker,
    MixtureOfAgents,
    PolicyAwareFallback,
    PolicyDegradationRefused,
    TieredConnector,
    moa_recommended,
)
from maestro.connectors.base import (
    ChatRequest,
    GenerationResult,
    ModelConnector,
    ProviderUnavailableError,
    Usage,
)


class _Fixed(ModelConnector):
    """A connector that returns a fixed text (no network)."""

    provider = "test"

    def __init__(self, name: str, text: str, *, enabled: bool = True) -> None:
        super().__init__(name, f"{name}-model", enabled=enabled)
        self._text = text

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        return GenerationResult(text=self._text, model=model, usage=Usage(1, 1))


class _Failing(ModelConnector):
    """A connector that is reachable but always fails (retryable)."""

    provider = "test"

    def __init__(self, name: str, *, enabled: bool = True) -> None:
        super().__init__(name, f"{name}-model", enabled=enabled)

    def _generate(self, request: ChatRequest, model: str) -> GenerationResult:
        raise ProviderUnavailableError("backend down", provider=self.provider)


_REQ = ChatRequest.of("assess the anomaly")


# --------------------------------------------------------------------------- #
# Latency-aware routing
# --------------------------------------------------------------------------- #
def test_router_explores_unmeasured_connectors_first():
    a, b = _Fixed("a", "x"), _Fixed("b", "y")
    router = LatencyAwareRouter([a, b])
    assert router.select() is a           # no samples yet → first in order


def test_router_exploits_lowest_p95():
    a, b = _Fixed("a", "x"), _Fixed("b", "y")
    tracker = LatencyTracker()
    for _ in range(5):
        tracker.record("a", 200.0)
        tracker.record("b", 40.0)
    router = LatencyAwareRouter([a, b], tracker=tracker)
    assert router.select() is b           # lower tail latency wins


def test_router_skips_disabled_connectors():
    a, b = _Fixed("a", "x"), _Fixed("b", "y")
    tracker = LatencyTracker()
    tracker.record("a", 10.0)
    tracker.record("b", 5.0)
    b.enabled = False
    router = LatencyAwareRouter([a, b], tracker=tracker)
    assert router.select() is a


def test_router_chat_records_latency():
    a = _Fixed("a", "hello")
    router = LatencyAwareRouter([a])
    resp = router.chat(_REQ)
    assert resp.text == "hello"
    assert router.tracker.samples("a")    # a latency sample was recorded


# --------------------------------------------------------------------------- #
# Policy-aware fallback (the ⚑ correction)
# --------------------------------------------------------------------------- #
def _chain():
    # frontier (tier 3) fails; local (tier 1) works.
    return PolicyAwareFallback([
        TieredConnector(_Failing("frontier"), tier=3),
        TieredConnector(_Fixed("local", "local answer"), tier=1),
    ])


def test_low_stakes_request_degrades_freely():
    # min_tier=0: the weak local backend is acceptable, so fallback proceeds.
    resp = _chain().chat(_REQ, min_tier=0)
    assert resp.text == "local answer"


def test_high_stakes_request_fails_closed_instead_of_downgrading():
    # min_tier=2: local (tier 1) is below the bar, so after frontier fails the
    # chain refuses to degrade — the security-critical behavior.
    with pytest.raises(PolicyDegradationRefused):
        _chain().chat(_REQ, min_tier=2)


def test_high_stakes_request_uses_an_eligible_high_tier_connector():
    chain = PolicyAwareFallback([
        TieredConnector(_Failing("frontier-a"), tier=3),
        TieredConnector(_Fixed("frontier-b", "frontier answer"), tier=3),
        TieredConnector(_Fixed("local", "local answer"), tier=1),
    ])
    # Degrades *within* the tier bar (frontier-a → frontier-b), never to local.
    assert chain.chat(_REQ, min_tier=2).text == "frontier answer"


def test_no_connector_meets_the_required_tier():
    chain = PolicyAwareFallback([TieredConnector(_Fixed("local", "x"), tier=1)])
    with pytest.raises(PolicyDegradationRefused):
        chain.chat(_REQ, min_tier=5)


# --------------------------------------------------------------------------- #
# Mixture of Agents
# --------------------------------------------------------------------------- #
def test_moa_consensus_low_disagreement():
    moa = MixtureOfAgents([
        _Fixed("a", "throttle telemetry now"),
        _Fixed("b", "throttle telemetry immediately"),
    ])
    result = moa.chat(_REQ)
    assert result.disagreement < 0.5
    assert not result.route_to_human
    assert result.response.text in result.proposer_texts   # medoid


def test_moa_disagreement_routes_to_human():
    moa = MixtureOfAgents([
        _Fixed("a", "throttle telemetry"),
        _Fixed("b", "delete all logs immediately"),
    ])
    result = moa.chat(_REQ)
    assert result.disagreement > 0.5
    assert result.route_to_human


def test_moa_uses_an_aggregator_when_provided():
    moa = MixtureOfAgents(
        [_Fixed("a", "answer one"), _Fixed("b", "answer two")],
        aggregator=_Fixed("agg", "synthesized consensus"))
    result = moa.chat(_REQ)
    assert result.response.text == "synthesized consensus"
    assert moa.cost_multiplier == 3          # 2 proposers + 1 aggregator


def test_moa_cost_multiplier_without_aggregator():
    moa = MixtureOfAgents([_Fixed("a", "x"), _Fixed("b", "y"), _Fixed("c", "z")])
    assert moa.cost_multiplier == 3


def test_moa_requires_at_least_two_proposers():
    with pytest.raises(ValueError):
        MixtureOfAgents([_Fixed("a", "x")])


def test_moa_recommended_targets_high_stakes_only():
    assert moa_recommended("require_approval")
    assert moa_recommended("emergency_containment")
    assert moa_recommended("allow", confidence=0.3)      # low confidence
    assert not moa_recommended("allow")
    assert not moa_recommended("allow_with_safeguards", confidence=0.9)
