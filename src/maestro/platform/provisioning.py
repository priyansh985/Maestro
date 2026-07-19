"""Automatic agent provisioning (blueprint §4.4) — secure by inheritance.

When a new provider/model is registered, the platform should be able to stand up
an agent for it *without* widening anyone's blast radius. The critical property
is **secure-by-inheritance**: a newly provisioned agent inherits an existing,
bounded :class:`PolicyEnvelope` — the same tenant, capability vocabulary, budget,
and TTLs as its cohort — rather than a fresh, permissive default. A new model is
not a reason to trust more.

:class:`AgentProvisioner` mints :class:`~maestro.platform.AgentPlatform`
instances under one envelope and one signing key (so the cohort shares a trust
root), records every provisioning in a tamper-evident ledger, and refuses to
provision for an unavailable provider. The envelope's ``allowed_intents`` is the
least-privilege lever: an agent for a lower-trust provider can be given a
strictly narrower vocabulary, and the gateway then denies anything outside it —
structurally, not by policy prose.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from ..security.budget import AutonomyBudget
from ..security.circuit_breaker import CircuitBreaker
from ..security.identity import SIGNING_KEY_ENV
from ..security.ledger import Ledger
from .agent_platform import AgentPlatform


class ProvisioningError(Exception):
    """Raised when an agent cannot be provisioned (e.g., provider unavailable)."""


@dataclass(frozen=True)
class PolicyEnvelope:
    """The bounded policy template a cohort of agents inherits.

    Everything an agent is *allowed* to be is captured here, so provisioning a
    new agent is "instantiate this envelope", never "start permissive and lock
    down later". ``allowed_intents=None`` means the full platform vocabulary;
    any tuple restricts it (least privilege).
    """

    tenant: str
    controller: str
    allowed_intents: tuple[str, ...] | None = None
    max_tool_calls: int | None = 1000
    max_spend: float | None = None
    max_affected: int | None = None
    window_seconds: float | None = 60.0
    max_calls_per_window: int | None = 120
    capability_ttl_s: float = 900.0
    breaker_max_repeats: int = 5
    breaker_window_s: float = 60.0

    def budget(self) -> AutonomyBudget:
        """A *fresh* budget instance — cohort agents never share budget state."""
        return AutonomyBudget(
            max_tool_calls=self.max_tool_calls,
            max_spend=self.max_spend,
            max_affected=self.max_affected,
            window_seconds=self.window_seconds,
            max_calls_per_window=self.max_calls_per_window,
        )

    def breaker(self) -> CircuitBreaker:
        """A *fresh* circuit breaker per agent."""
        return CircuitBreaker(
            max_repeats=self.breaker_max_repeats, window_seconds=self.breaker_window_s)

    def digest(self) -> str:
        intents = "*" if self.allowed_intents is None else ",".join(sorted(self.allowed_intents))
        return (f"tenant={self.tenant};intents={intents};calls={self.max_tool_calls};"
                f"rate={self.max_calls_per_window}/{self.window_seconds}s;ttl={self.capability_ttl_s}")


@dataclass(frozen=True)
class ProvisionedAgent:
    """Record of one provisioning (what was stood up, for which provider)."""

    agent_id: str
    provider: str
    platform: AgentPlatform = field(repr=False)


class AgentProvisioner:
    """Stands up agents under a single :class:`PolicyEnvelope` and trust root."""

    def __init__(
        self,
        envelope: PolicyEnvelope,
        *,
        key: bytes | str | None = None,
        ledger: Ledger | None = None,
    ) -> None:
        resolved_key = key or os.environ.get(SIGNING_KEY_ENV) or secrets.token_hex(32)
        self._envelope = envelope
        self._key = resolved_key
        self._ledger = ledger if ledger is not None else Ledger(key=resolved_key)
        self._agents: dict[str, ProvisionedAgent] = {}

    @property
    def envelope(self) -> PolicyEnvelope:
        return self._envelope

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def agents(self) -> dict[str, ProvisionedAgent]:
        return dict(self._agents)

    def provision(
        self,
        agent_id: str,
        *,
        reasoner: object | None = None,
        provider: str = "stub",
    ) -> AgentPlatform:
        """Instantiate the envelope as a new agent bound to ``reasoner``.

        The agent gets *exactly* the envelope's blast radius — same intent
        vocabulary, same budget ceilings, same TTLs — under a capability
        delegated from the envelope's controller. The provisioning is recorded.
        """
        if agent_id in self._agents:
            raise ProvisioningError(f"agent {agent_id!r} is already provisioned")

        platform = AgentPlatform(
            reasoner=reasoner,
            tenant=self._envelope.tenant,
            controller=self._envelope.controller,
            agent_id=agent_id,
            key=self._key,
            allowed_intents=self._envelope.allowed_intents,
            budget=self._envelope.budget(),
            breaker=self._envelope.breaker(),
            capability_ttl_s=self._envelope.capability_ttl_s,
        )
        self._ledger.append(
            event_type="agent_provisioned",
            actor_identity=self._envelope.controller,
            decision="provision",
            input_hash="",
            policy_digest=self._envelope.digest(),
            detail={"agent_id": agent_id, "provider": provider,
                    "tenant": self._envelope.tenant},
        )
        self._agents[agent_id] = ProvisionedAgent(agent_id, provider, platform)
        return platform

    def provision_for_connector(
        self, agent_id: str, connector: object, *, provider: str,
    ) -> AgentPlatform:
        """Provision an agent whose reasoner is a registered model connector.

        This is the listener a provider-registration event would call. It is
        health-gated: an absent/unavailable connector is refused rather than
        provisioned into a broken agent.
        """
        if connector is None:
            raise ProvisioningError(f"provider {provider!r} is unavailable; refusing to provision")
        from ..agent.reasoning import ConnectorReasoner

        return self.provision(
            agent_id, reasoner=ConnectorReasoner(connector), provider=provider)  # type: ignore[arg-type]
