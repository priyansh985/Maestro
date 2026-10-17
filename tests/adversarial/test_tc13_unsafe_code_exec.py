"""TC13: Unsafe Code Execution Test.

Tests that Docker/gVisor confinement and scope enforcement work.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from maestro.security.action import ActionProposal
from maestro.security.sandbox import ExecutionSandbox, SandboxPolicy, SandboxViolation


class TestTC13UnsafeCodeExecution:
    """TC13 - Unsafe code execution must be confined."""

    @pytest.fixture
    def sandbox(self):
        return ExecutionSandbox(policy=SandboxPolicy())

    def test_adapter_cannot_claim_different_target(self, sandbox):
        """Adapter cannot claim a target outside authorized scope."""
        def malicious_adapter(p):
            return {"ok": True, "target": "different:resource", "effect": "hacked"}
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:authorized",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        with pytest.raises(SandboxViolation, match="outside authorized scope"):
            sandbox.run(malicious_adapter, proposal)

    def test_adapter_output_size_limited(self, sandbox):
        """Adapter output size is limited."""
        def oversized_adapter(p):
            return {"ok": True, "data": "x" * 1000000}  # 1MB output
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        with pytest.raises(SandboxViolation, match="exceeds.*byte cap"):
            sandbox.run(oversized_adapter, proposal)

    def test_adapter_output_must_be_json_serializable(self, sandbox):
        """Adapter output must be JSON serializable dict."""
        def non_json_adapter(p):
            return {1, 2, 3}  # Not a dict, not JSON serializable
        
        proposal = ActionProposal(
            intent="noop",
            target="agent:self",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        with pytest.raises(SandboxViolation, match="not a dict"):
            sandbox.run(non_json_adapter, proposal)

    @patch("subprocess.run")
    def test_docker_sandbox_isolation(self, mock_run, sandbox):
        """Docker sandbox isolates execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true, "effect": "isolated", "target": "code:repo:test"}',
            stderr=""
        )
        
        policy = SandboxPolicy(use_external=True, sandbox_type="docker", timeout_s=30)
        docker_sandbox = ExecutionSandbox(policy=policy)
        
        def adapter(p):
            return {"ok": True, "effect": "test", "target": p.target}
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        result, replayed = docker_sandbox.run(adapter, proposal)
        assert result["ok"] is True
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_gvisor_sandbox_isolation(self, mock_run, sandbox):
        """gVisor sandbox isolates execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true, "effect": "isolated", "target": "code:repo:test"}',
            stderr=""
        )
        
        policy = SandboxPolicy(use_external=True, sandbox_type="gvisor", timeout_s=30)
        gvisor_sandbox = ExecutionSandbox(policy=policy)
        
        def adapter(p):
            return {"ok": True, "effect": "test", "target": p.target}
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        result, replayed = gvisor_sandbox.run(adapter, proposal)
        assert result["ok"] is True
        mock_run.assert_called_once()

    def test_sandbox_timeout_enforced(self, sandbox):
        """Sandbox enforces timeout on adapter execution."""
        import time
        
        def slow_adapter(p):
            time.sleep(2)  # Longer than default timeout
            return {"ok": True, "target": p.target}
        
        policy = SandboxPolicy(timeout_s=0.5)  # 500ms timeout
        timeout_sandbox = ExecutionSandbox(policy=policy)
        
        proposal = ActionProposal(
            intent="code_write",
            target="code:repo:test",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )
        
        with pytest.raises(SandboxViolation, match="timeout"):
            timeout_sandbox.run(slow_adapter, proposal)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])