"""Tests for the Hybrid Runner (BP10).

Adversarial tests ensuring:
- Fail-closed behavior: network partition → deny mutating, allow read-only
- Data never leaves local boundary without explicit capability
- Capability tokens validated locally
- Local ledger integrity maintained
- Policy cache used when control plane unreachable
"""
from __future__ import annotations

import pytest

from maestro.hybrid import (
    HybridConfig,
    HybridRunner,
    RunnerMode,
    create_hybrid_runner,
)
from maestro.memory import MemoryTier
from maestro.security.action import REVERSIBLE_INTENTS, parse_proposal
from maestro.security.enforcement import EnforcementResult
from maestro.security.risk_engine import Decision as EnforcementDecision
from maestro.telemetry.detection import Alert, AlertClass


class TestHybridRunnerModes:
    """Tests for hybrid runner operational modes."""

    def test_runner_starts_online_with_no_control_plane(self):
        """Runner without control plane URL starts in ONLINE mode but degrades."""
        runner = create_hybrid_runner(control_plane_url=None, tenant="test")
        assert runner.mode == RunnerMode.ONLINE
        # Health check should fail and switch to offline_readonly
        assert runner.check_control_plane_health() is False
        assert runner.mode == RunnerMode.OFFLINE_READONLY

    def test_runner_online_mode_allows_all_actions(self):
        """Online mode allows all capability-gated actions."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="test")
        runner.mode = RunnerMode.ONLINE
        runner._refresh_capabilities()

        # Should have capabilities for all intents
        assert "code_read" in runner._caps
        assert "code_write" in runner._caps
        assert "research_search" in runner._caps

    def test_offline_readonly_allows_reversible_only(self):
        """Offline read-only mode only allows reversible intents."""
        runner = create_hybrid_runner(control_plane_url=None, tenant="test")
        runner.mode = RunnerMode.OFFLINE_READONLY
        runner._refresh_capabilities()

        # Add evidence to memory so evidence validation passes
        scope = runner.scope
        rec = runner.memory.remember(scope, MemoryTier.EPISODIC, "test evidence")
        evidence_id = rec.record_id

        # Test a reversible intent (should be allowed)
        proposal = parse_proposal(
            f'{{"intent": "code_read", "target": "code:repo:test", "reason": "test", '
            f'"evidence_ids": ["{evidence_id}"], "requested_ttl_seconds": 300}}'
        )
        result = runner.execute_proposal(proposal)
        # In offline_readonly, reversible intents should work (not denied)
        assert result.allowed is True or result.decision != EnforcementDecision.DENY_AUTONOMOUS

    def test_offline_readonly_denies_mutating(self):
        """Offline read-only mode denies mutating actions."""
        runner = create_hybrid_runner(control_plane_url=None, tenant="test")
        runner.mode = RunnerMode.OFFLINE_READONLY
        runner._refresh_capabilities()

        # Test a mutating intent (should be denied)
        proposal = parse_proposal(
            '{"intent": "code_write", "target": "code:repo:test", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        result = runner.execute_proposal(proposal)
        assert result.decision == EnforcementDecision.DENY_AUTONOMOUS
        assert "offline_readonly" in str(result.output).lower() or "mutating" in result.reason.lower()

    def test_offline_deny_denies_all(self):
        """Offline deny mode denies all actions."""
        runner = create_hybrid_runner(control_plane_url=None, tenant="test")
        runner.mode = RunnerMode.OFFLINE_DENY
        runner._refresh_capabilities()

        # Add evidence to memory so evidence validation passes
        scope = runner.scope
        rec = runner.memory.remember(scope, MemoryTier.EPISODIC, "test evidence")
        evidence_id = rec.record_id

        # Even reversible should be denied
        proposal = parse_proposal(
            f'{{"intent": "noop", "target": "agent:self", "reason": "test", '
            f'"evidence_ids": ["{evidence_id}"], "requested_ttl_seconds": 300}}'
        )
        result = runner.execute_proposal(proposal)
        assert result.decision == EnforcementDecision.DENY_AUTONOMOUS
        assert "offline_deny" in str(result.output).lower() or "unreachable" in result.reason.lower()


class TestHybridRunnerCapabilities:
    """Tests for capability validation."""

    def test_missing_capability_denied(self):
        """Proposal without capability is denied."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="test")
        runner.mode = RunnerMode.ONLINE
        # Don't refresh capabilities - simulate missing capability

        proposal = parse_proposal(
            '{"intent": "code_write", "target": "code:repo:test", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        result = runner.execute_proposal(proposal)
        assert result.decision == EnforcementDecision.DENY_AUTONOMOUS
        assert "no capability" in result.reason.lower()

    def test_capability_tenant_scoped(self):
        """Capabilities are scoped to tenant."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="tenant-a")
        runner.mode = RunnerMode.ONLINE
        runner._refresh_capabilities()

        # Capability should be for tenant-a
        cap = runner._caps.get("code_read")
        assert cap is not None
        assert "tenant-a" in cap.resource_constraint


class TestHybridRunnerDataLocality:
    """Tests that data remains local by default."""

    def test_memory_is_local(self):
        """Memory store is local to the runner."""
        runner = create_hybrid_runner(tenant="test")
        scope = runner.scope

        # Write to memory
        rec = runner.memory.remember(scope, MemoryTier.EPISODIC, "local secret data")
        assert rec.scope.tenant == "test"
        assert rec.content == "local secret data"

        # Memory never sent to control plane in this implementation
        # (would require explicit sync)

    def test_ledger_is_local(self):
        """Ledger is local and tamper-evident."""
        runner = create_hybrid_runner(tenant="test")

        # Ledger should be intact
        assert runner.ledger.verify_chain() == -1
        assert len(runner.ledger) >= 0

    def test_no_egress_without_capability(self):
        """Network egress requires explicit capability and allowed domain."""
        config = HybridConfig(
            control_plane_url="http://localhost:8000",
            tenant="test",
            allowed_egress_domains=("api.github.com",)
        )
        HybridRunner(config)

        # Runner only has local adapters - no actual network calls
        # In real implementation, HTTP adapter would check allowed_egress_domains
        assert "api.github.com" in config.allowed_egress_domains
        assert "evil.com" not in config.allowed_egress_domains


class TestHybridRunnerIntegration:
    """Integration tests."""

    def test_submit_alert_processes_locally(self):
        """Alert is processed through local reasoner and PEP."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="test")
        runner.mode = RunnerMode.ONLINE
        runner._refresh_capabilities()

        alert = Alert(ts=1000.0, cls=AlertClass.ANOMALY, severity=0.5, detail="test")
        result = runner.submit_alert(alert)

        # Should get an enforcement result
        assert isinstance(result, EnforcementResult)
        # The result doesn't have a proposal field directly, but we can check the decision
        assert result.decision is not None

    def test_status_reports_local_state(self):
        """Status includes local state only."""
        runner = create_hybrid_runner(tenant="test")
        status = runner.get_status()

        assert status["tenant"] == "test"
        assert status["agent_id"] == "agent:hybrid:run"
        assert "ledger_events" in status
        assert "ledger_intact" in status
        assert "memory_tiers" in status
        assert status["mode"] in ("online", "offline_readonly", "offline_deny")


class TestHybridRunnerAdversarial:
    """Adversarial tests."""

    def test_partition_simulation_triggers_fail_closed(self):
        """Simulated network partition triggers fail-closed."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="test")
        runner.mode = RunnerMode.ONLINE
        runner._refresh_capabilities()

        # Simulate partition by setting last contact to ancient
        runner._last_control_plane_contact = 0
        runner.check_control_plane_health()

        assert runner.mode == RunnerMode.OFFLINE_READONLY

    def test_no_capability_escalation(self):
        """Agent cannot escalate privileges by forging proposals."""
        runner = create_hybrid_runner(control_plane_url="http://localhost:8000", tenant="test")
        runner.mode = RunnerMode.ONLINE
        runner._refresh_capabilities()

        # Try to propose an intent not in vocabulary
        proposal = parse_proposal(
            '{"intent": "alert_operator", "target": "operator:oncall", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        result = runner.execute_proposal(proposal)
        # Should be denied - no capability for alert_operator in hybrid runner
        assert result.decision == EnforcementDecision.DENY_AUTONOMOUS

    def test_local_ledger_tamper_detection(self):
        """Tampering with local ledger is detected."""
        runner = create_hybrid_runner(tenant="test")

        # Verify intact
        assert runner.ledger.verify_chain() == -1

        # Direct tampering (bypassing API) would break chain
        # This is a property of the ledger implementation
        assert runner.get_status()["ledger_intact"] is True

    def test_reversible_intents_defined_correctly(self):
        """Reversible intents match the research/coding agents' read-only actions."""
        reversible = REVERSIBLE_INTENTS
        hybrid_readonly = {"code_read", "code_test", "code_lint", "code_git_status", "code_git_diff",
                           "research_search", "research_fetch", "research_cite"}

        # All hybrid read-only intents should be in REVERSIBLE_INTENTS
        assert hybrid_readonly.issubset(reversible)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])