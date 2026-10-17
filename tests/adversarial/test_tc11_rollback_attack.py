"""TC11: Rollback Attack Test.

Tests that exactly-once prevents replay and compensation is recorded.
"""
from __future__ import annotations

from contextlib import suppress

import pytest

from maestro.orchestration.journal import Journal
from maestro.security.action import ActionProposal
from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy


class TestTC11RollbackAttack:
    """TC11 - Rollback attack must be prevented by exactly-once execution."""

    @pytest.fixture
    def sandbox(self):
        journal = Journal()
        return ExecutionSandbox(policy=SandboxPolicy(), journal=journal), journal

    def test_idempotent_execution_prevents_replay(self, sandbox):
        """Same idempotency key replays result instead of re-executing."""
        sandbox_obj, journal = sandbox
        
        call_count = 0
        
        def adapter(p):
            nonlocal call_count
            call_count += 1
            return {"ok": True, "effect": f"execution_{call_count}", "target": p.target}
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
            action_class="code_execution",
            capability="cap:code:write",
        )
        
        # First execution
        result1, replayed1 = sandbox_obj.run(adapter, proposal, idempotency_key="key-1")
        assert replayed1 is False
        assert call_count == 1
        
        # Second execution with same key should replay
        result2, replayed2 = sandbox_obj.run(adapter, proposal, idempotency_key="key-1")
        assert replayed2 is True
        assert call_count == 1  # Adapter not called again
        assert result1 == result2

    def test_journal_records_completion(self, sandbox):
        """Journal records completed activities."""
        sandbox_obj, journal = sandbox
        
        def adapter(p):
            return {"ok": True, "effect": "test", "target": p.target}
        
        proposal = ActionProposal(
            intent="noop",
            target="agent:self",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        sandbox_obj.run(adapter, proposal, idempotency_key="key-2")
        
        records = journal.records_for("key-2")
        assert len(records) == 1
        assert records[0].status == "completed"
        assert records[0].name == "noop"

    def test_failed_activity_recorded(self, sandbox):
        """Failed activities are recorded in journal."""
        sandbox_obj, journal = sandbox
        
        def failing_adapter(p):
            raise Exception("Adapter failed")
        
        proposal = ActionProposal(
            intent="noop",
            target="agent:self",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        with suppress(Exception):
            sandbox_obj.run(failing_adapter, proposal, idempotency_key="key-3")
        
        records = journal.records_for("key-3")
        assert len(records) == 1
        assert records[0].status == "failed"

    def test_crash_recovery_replays_completed(self, sandbox):
        """Simulated crash recovery replays completed activities."""
        sandbox_obj, journal = sandbox
        
        def adapter(p):
            return {"ok": True, "effect": "test", "target": p.target}
        
        proposal = ActionProposal(
            intent="code_read",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        # Execute once
        sandbox_obj.run(adapter, proposal, idempotency_key="key-4")
        
        # Simulate new sandbox instance with same journal (crash recovery)
        from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy
        new_sandbox = ExecutionSandbox(policy=SandboxPolicy(), journal=journal)
        
        # Re-execution should replay
        result, replayed = new_sandbox.run(adapter, proposal, idempotency_key="key-4")
        assert replayed is True
        assert result["effect"] == "test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])