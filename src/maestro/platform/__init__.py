"""MAESTRO-SecOps agent platform — the live control loop.

This package is the keystone integration: it makes the security control plane
*the* execution path rather than a set of standalone components. The loop
embodies the platform's one principle —

    An LLM proposes intentions; deterministic services authorize, execute,
    verify, and record consequences.

concretely: a telemetry alert → the reasoner (LLM via the connector layer, or
the offline stub) **proposes** a typed action → the
:class:`~maestro.security.enforcement.PolicyEnforcementPoint` **authorizes,
executes, verifies, and records** it under a scoped capability, with risk
scoring, action confidence, autonomy budget, a circuit breaker, and a
tamper-evident ledger. There is no code path from a model output to a side
effect that bypasses the enforcement point — which is what lets the truth audit
grade these controls ``enforced`` rather than merely ``implemented``.
"""
from __future__ import annotations

from .agent_platform import (
    AgentPlatform,
    PlatformResult,
    default_tool_adapters,
    shadow_tool_adapters,
)
from .blast_radius import BlastRadius
from .provisioning import (
    AgentProvisioner,
    PolicyEnvelope,
    ProvisionedAgent,
    ProvisioningError,
)

__all__ = [
    "AgentPlatform",
    "AgentProvisioner",
    "BlastRadius",
    "PlatformResult",
    "PolicyEnvelope",
    "ProvisionedAgent",
    "ProvisioningError",
    "default_tool_adapters",
    "shadow_tool_adapters",
]
