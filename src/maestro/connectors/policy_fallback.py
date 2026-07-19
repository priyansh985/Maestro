"""Policy-aware fallback (blueprint §6 — the ⚑ correction).

Ordinary "transparent" fallback (`fallback.py`) tries the next connector on any
retryable failure. That is a **security regression disguised as resilience**: on
a high-stakes request it will silently drop from a frontier model to a weak
local one that clears a *lower* bar — availability quietly eroding the policy
posture.

:class:`PolicyAwareFallback` fixes this. Each connector is tagged with a
capability/trust **tier**; a request declares the **minimum tier** its policy
requires. Fallback degrades *only within* connectors that still meet the bar —
and if none remain, it **fails closed** (:class:`PolicyDegradationRefused`)
instead of downgrading. A low-stakes request (``min_tier=0``) still degrades
freely; a high-stakes one never silently drops below its floor.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .base import (
    ChatRequest,
    ChatResponse,
    ConnectorError,
    ModelConnector,
)


class PolicyDegradationRefused(ConnectorError):
    """No connector meeting the required policy tier is available.

    Raised instead of silently degrading a high-stakes request to a
    lower-posture backend — the caller should route to a human / defer.
    """


@dataclass(frozen=True)
class TieredConnector:
    """A connector plus the policy tier it satisfies (higher = more trusted)."""

    connector: ModelConnector
    tier: int


class PolicyAwareFallback:
    """A fallback chain that will not degrade below a request's required tier."""

    def __init__(self, tiered: Sequence[TieredConnector]) -> None:
        if not tiered:
            raise ValueError("PolicyAwareFallback requires at least one connector")
        self._tiered = tuple(tiered)

    def chat(self, request: ChatRequest, *, min_tier: int = 0) -> ChatResponse:
        """Try tier-eligible connectors (best tier first); fail closed if none clear.

        A non-retryable error (bad request / auth) is raised immediately — a
        different backend will not fix a malformed request.
        """
        # Best tier first, but never below the required floor.
        eligible = sorted(
            (t for t in self._tiered if t.tier >= min_tier and t.connector.enabled),
            key=lambda t: t.tier, reverse=True,
        )
        if not eligible:
            raise PolicyDegradationRefused(
                f"no connector at policy tier >= {min_tier}; refusing to downgrade")

        last_error: ConnectorError | None = None
        for entry in eligible:
            try:
                return entry.connector.chat(request)
            except ConnectorError as exc:
                last_error = exc
                if not exc.retryable:
                    raise  # bad request / auth — not a resilience problem
        # Every tier-satisfying connector failed. Do NOT drop below the floor.
        raise PolicyDegradationRefused(
            f"all connectors at tier >= {min_tier} failed; refusing to degrade "
            "to a lower-posture backend"
        ) from last_error
