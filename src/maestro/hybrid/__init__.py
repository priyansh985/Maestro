"""Hybrid Runner & Local Data Plane (BP10).

Enables private execution near customer data — raw sensitive data remains
local by default. The local runner connects to the central control plane
for policy/authorization but executes tool calls locally.

Fail-closed behavior: if control plane unreachable → deny all mutating actions,
allow read-only.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from maestro.memory import MemoryScope, MemoryStore, MemoryTier
from maestro.orchestration.journal import Journal
from maestro.security.action import (
    INTENT_REGISTRY,
    REVERSIBLE_INTENTS,
    ActionProposal,
    parse_proposal,
)
from maestro.security.budget import AutonomyBudget
from maestro.security.circuit_breaker import CircuitBreaker
from maestro.security.enforcement import (
    ActionState,
    EnforcementResult,
    PolicyEnforcementPoint,
    ToolAdapter,
)
from maestro.security.identity import CapabilityIssuer, CapabilityToken
from maestro.security.ledger import Ledger
from maestro.security.risk_engine import Decision as EnforcementDecision
from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy
from maestro.telemetry.detection import Alert


class RunnerMode(Enum):
    """Execution mode for the hybrid runner."""
    ONLINE = "online"          # Connected to control plane
    OFFLINE_READONLY = "offline_readonly"  # Partitioned - read only
    OFFLINE_DENY = "offline_deny"  # Partitioned - deny all


@dataclass
class HybridConfig:
    """Configuration for the hybrid runner."""
    control_plane_url: str | None = None
    tenant: str = "default"
    agent_id: str = "agent:hybrid:run"
    signing_key: bytes | None = None
    policy_cache_path: str | None = None
    ledger_path: str | None = None
    journal_path: str | None = None
    allowed_egress_domains: tuple[str, ...] = ()
    max_offline_duration_s: float = 300.0  # 5 minutes before forcing offline mode


# Local intent resource mapping (mirrors agent_platform.py)
_INTENT_RESOURCE: dict[str, str] = {
    "noop": "agent:self",
    "throttle_telemetry": "telemetry:ws-stream",
    "raise_thresholds": "detection:thresholds",
    "raise_capture_duration": "capture:params",
    "alert_operator": "operator:oncall",
    "rollback_telemetry": "telemetry:checkpoint",
    "promote_memory": "memory:{tenant}",
    "code_read": "code:repo:{tenant}",
    "code_write": "code:repo:{tenant}",
    "code_test": "code:repo:{tenant}",
    "code_lint": "code:repo:{tenant}",
    "code_git_status": "code:repo:{tenant}",
    "code_git_diff": "code:repo:{tenant}",
    "code_git_push": "code:repo:{tenant}",
    "code_open_pr": "code:repo:{tenant}",
    "research_search": "research:sources:{tenant}",
    "research_fetch": "research:sources:{tenant}",
    "research_cite": "research:sources:{tenant}",
    "research_synthesize": "research:report:{tenant}",
}


class HybridRunner:
    """Local executor that connects to central control plane for authorization.

    Architecture:
    - Local: tool execution, sandbox, journal, ledger replica, policy cache
    - Remote: policy registry, capability issuance, central ledger, audit
    - Fail-closed: network partition → deny mutating, allow read-only
    """

    def __init__(self, config: HybridConfig):
        self.config = config
        self.mode = RunnerMode.ONLINE
        self._last_control_plane_contact = time.time()
        self._policy_cache: dict[str, Any] = {}

        # Resolve signing key
        self.signing_key = config.signing_key or secrets.token_bytes(32)

        # Local components (always available)
        self.issuer = CapabilityIssuer(key=self.signing_key)
        self.ledger = Ledger(key=self.signing_key)
        self.journal = Journal(config.journal_path)
        self.sandbox = ExecutionSandbox(policy=SandboxPolicy(), journal=self.journal)
        self.budget = AutonomyBudget(
            max_tool_calls=1000, window_seconds=60.0, max_calls_per_window=120)
        self.breaker = CircuitBreaker(max_repeats=5, window_seconds=60.0)

        # Memory store (local, tenant-scoped)
        self.memory = MemoryStore(issuer=self.issuer, ledger=self.ledger)
        self.scope = MemoryScope(config.tenant, config.agent_id)

        # Policy enforcement point (local, uses cached policies)
        self.pep = PolicyEnforcementPoint(
            issuer=self.issuer,
            ledger=self.ledger,
            evidence_exists=self._evidence_exists,
            tenant=config.tenant,
            adapters=self._local_adapters(),
            budget=self.budget,
            breaker=self.breaker,
            sandbox=self.sandbox,
            pre_execution_gate=None,  # No critique gate in hybrid by default
            policy_registry=None,  # Uses local policy cache
        )

        # Delegated capabilities (issued at startup if online)
        self._caps: dict[str, CapabilityToken] = {}

    def _local_adapters(self) -> dict[str, ToolAdapter]:
        """Local tool adapters for offline execution."""
        def _effect(effect: str) -> ToolAdapter:
            def adapter(p: ActionProposal) -> dict:
                return {"ok": True, "effect": effect, "target": p.target}
            return adapter

        return {
            "noop": lambda p: {"ok": True, "effect": "no-op"},
            "code_read": _effect("code read"),
            "code_write": _effect("code written"),
            "code_test": _effect("tests executed"),
            "code_lint": _effect("lint executed"),
            "code_git_status": _effect("git status retrieved"),
            "code_git_diff": _effect("git diff retrieved"),
            "research_search": _effect("local search executed"),
            "research_fetch": _effect("local source fetched"),
            "research_cite": _effect("citation verified"),
            "research_synthesize": _effect("report synthesized"),
        }

    def _evidence_exists(self, evidence_id: str) -> bool:
        return self.memory.exists(evidence_id, self.scope)

    def check_control_plane_health(self) -> bool:
        """Check if control plane is reachable.

        In a real implementation, this would make an HTTP request to the
        control plane's /healthz endpoint. For now, we simulate based on
        config and time since last contact.
        """
        # Don't override OFFLINE_DENY mode - it's a forced state
        if self.mode == RunnerMode.OFFLINE_DENY:
            return False

        if self.config.control_plane_url is None:
            # No control plane configured -> offline read-only
            self.mode = RunnerMode.OFFLINE_READONLY
            return False

        elapsed = time.time() - self._last_control_plane_contact
        if elapsed > self.config.max_offline_duration_s:
            self.mode = RunnerMode.OFFLINE_READONLY
            return False

        # Simulate successful contact
        self._last_control_plane_contact = time.time()
        if self.mode != RunnerMode.ONLINE:
            self.mode = RunnerMode.ONLINE
            self._refresh_capabilities()
        return True

    def _refresh_capabilities(self):
        """Refresh capabilities from control plane (simulated)."""
        # In real implementation: fetch from control plane /api/capabilities
        # For now, issue local capabilities
        vocabulary = ("code_read", "code_write", "code_test", "code_lint",
                      "code_git_status", "code_git_diff",
                      "research_search", "research_fetch", "research_cite", "research_synthesize")

        self._caps = {}
        for intent in vocabulary:
            if intent in INTENT_REGISTRY and intent in _INTENT_RESOURCE:
                resource = _INTENT_RESOURCE[intent].replace("{tenant}", self.config.tenant)
                capability = INTENT_REGISTRY[intent][1]
                self._caps[intent] = self.issuer.issue(
                    subject=self.config.agent_id,
                    capability=capability,
                    resource_constraint=resource,
                    tenant=self.config.tenant,
                    ttl_seconds=3600.0,
                    delegation_depth=1,
                    parent="control-plane:admin"
                )

    def execute_proposal(self, proposal: ActionProposal) -> EnforcementResult:
        """Execute a proposal through the local enforcement point.

        Fail-closed logic:
        - ONLINE: full enforcement with capability check
        - OFFLINE_READONLY: only allow reversible/read intents
        - OFFLINE_DENY: deny all
        """
        # Check control plane health
        self.check_control_plane_health()

        # Fail-closed: check mode
        if self.mode == RunnerMode.OFFLINE_DENY:
            return EnforcementResult(
                allowed=False,
                decision=EnforcementDecision.DENY_AUTONOMOUS,
                reason="Control plane unreachable - fail-closed deny",
                residual_risk=5.0,
                output={"error": "offline_deny"},
                state=ActionState.DENIED,
            )

        if self.mode == RunnerMode.OFFLINE_READONLY and proposal.intent not in REVERSIBLE_INTENTS:
            return EnforcementResult(
                allowed=False,
                decision=EnforcementDecision.DENY_AUTONOMOUS,
                reason="Offline read-only mode - mutating action denied",
                residual_risk=5.0,
                output={"error": "offline_readonly"},
                state=ActionState.DENIED,
            )

        # Check capability
        if proposal.intent not in self._caps:
            return EnforcementResult(
                allowed=False,
                decision=EnforcementDecision.DENY_AUTONOMOUS,
                reason=f"No capability for intent: {proposal.intent}",
                residual_risk=5.0,
                output={"error": "no_capability"},
                state=ActionState.DENIED,
            )

        # Execute through PEP
        # Build minimal risk inputs for local execution
        from maestro.security.risk_engine import RiskInputs
        risk = RiskInputs(
            likelihood=1.0, impact=1.0, exploitability=1.0,
            exposure=1.0, detectability_inverse=1.0,
            recoverability_inverse=1.0, blast_radius=1.0
        )
        return self.pep.authorize_and_execute(
            proposal,
            token=self._caps[proposal.intent],
            risk=risk,
            actor=self.config.agent_id,
            controls=None,
            confidence=None,
            cost=0.0,
            affected=0,
            idempotency_key=None,
            verification_context=None,
        )

    def submit_alert(self, alert: Alert) -> EnforcementResult:
        """Submit an alert for local processing.

        This runs the local reasoner (stub) and executes the proposed action.
        """
        from maestro.agent.reasoning import StubReasoner
        reasoner = StubReasoner()
        result = reasoner.reason(alert)

        # Build proposal
        action_class, capability = INTENT_REGISTRY.get(result.action, ("unknown", ""))

        proposal = ActionProposal(
            intent=result.action,
            target=_INTENT_RESOURCE.get(result.action, "unknown").replace("{tenant}", self.config.tenant),
            reason=result.summary,
            evidence_ids=(f"alert:{alert.cls.value}:{int(alert.ts)}",),
            requested_ttl_seconds=300,
            action_class=action_class,
            capability=capability,
        )

        return self.execute_proposal(proposal)

    def get_status(self) -> dict[str, Any]:
        """Get runner status for monitoring."""
        # Count records per tier using recall with include_untrusted=True
        memory_tiers = {}
        for tier in MemoryTier:
            records = self.memory.recall(self.scope, tier=tier, include_untrusted=True)
            memory_tiers[tier.value] = len(records)

        return {
            "mode": self.mode.value,
            "tenant": self.config.tenant,
            "agent_id": self.config.agent_id,
            "control_plane_url": self.config.control_plane_url,
            "last_contact_seconds_ago": time.time() - self._last_control_plane_contact,
            "capabilities": list(self._caps.keys()),
            "ledger_events": len(self.ledger),
            "ledger_intact": self.ledger.verify_chain() == -1,
            "memory_tiers": memory_tiers,
        }


def create_hybrid_runner(
    control_plane_url: str | None = None,
    tenant: str = "default",
    agent_id: str = "agent:hybrid:run",
    signing_key: bytes | None = None,
    policy_cache_path: str | None = None,
    ledger_path: str | None = None,
    journal_path: str | None = None,
) -> HybridRunner:
    """Factory for creating a hybrid runner."""
    config = HybridConfig(
        control_plane_url=control_plane_url,
        tenant=tenant,
        agent_id=agent_id,
        signing_key=signing_key,
        policy_cache_path=policy_cache_path,
        ledger_path=ledger_path,
        journal_path=journal_path,
    )
    return HybridRunner(config)


def hybrid_runner_cli():
    """CLI entry point for the hybrid runner."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="MAESTRO Hybrid Runner")
    parser.add_argument("--config", type=str, help="Path to config YAML")
    parser.add_argument("--control-plane", type=str, help="Control plane URL")
    parser.add_argument("--tenant", type=str, default="default", help="Tenant ID")
    parser.add_argument("--agent-id", type=str, default="agent:hybrid:run", help="Agent ID")
    parser.add_argument("--signing-key", type=str, help="Base64-encoded signing key")
    parser.add_argument("--status", action="store_true", help="Print status and exit")
    parser.add_argument("--execute", type=str, help="Execute a proposal (JSON)")

    args = parser.parse_args()

    # Load config if provided
    config_kwargs = {}
    if args.config:
        import yaml
        with open(args.config) as f:
            config_kwargs = yaml.safe_load(f)

    # Override with CLI args
    if args.control_plane:
        config_kwargs["control_plane_url"] = args.control_plane
    config_kwargs["tenant"] = args.tenant
    config_kwargs["agent_id"] = args.agent_id
    if args.signing_key:
        import base64
        config_kwargs["signing_key"] = base64.b64decode(args.signing_key)

    runner = create_hybrid_runner(**config_kwargs)

    if args.status:
        print(json.dumps(runner.get_status(), indent=2))
        return

    if args.execute:
        proposal = parse_proposal(args.execute)
        result = runner.execute_proposal(proposal)
        print(json.dumps(result.as_dict(), indent=2))
        return

    # Default: run as daemon (simplified)
    print(f"Hybrid runner started for tenant={args.tenant}, agent={args.agent_id}")
    print(f"Mode: {runner.mode.value}")
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(10)
            runner.check_control_plane_health()
            status = runner.get_status()
            print(f"Status: {status['mode']}, ledger: {status['ledger_events']} events")
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == "__main__":
    hybrid_runner_cli()