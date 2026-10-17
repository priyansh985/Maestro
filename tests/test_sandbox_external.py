"""Tests for external sandbox support (BP4)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from maestro.orchestration.journal import Journal
from maestro.security.action import ActionProposal
from maestro.security.sandbox import (
    ExecutionSandbox,
    SandboxPolicy,
    SandboxViolation,
    create_sandbox_from_config,
)


class TestSandboxPolicy:
    """Tests for SandboxPolicy configuration."""

    def test_default_policy_is_in_process(self):
        """Default policy should be in-process (no external sandbox)."""
        policy = SandboxPolicy()
        assert policy.use_external is False
        assert policy.timeout_s == 0.0
        assert policy.max_output_bytes == 64 * 1024

    def test_external_policy_config(self):
        """External sandbox policy can be configured."""
        policy = SandboxPolicy(
            use_external=True,
            sandbox_type="docker",
            sandbox_image="custom:latest",
            timeout_s=30.0,
        )
        assert policy.use_external is True
        assert policy.sandbox_type == "docker"
        assert policy.sandbox_image == "custom:latest"
        assert policy.timeout_s == 30.0

    def test_gvisor_policy_config(self):
        """gVisor sandbox policy can be configured."""
        policy = SandboxPolicy(
            use_external=True,
            sandbox_type="gvisor",
        )
        assert policy.sandbox_type == "gvisor"


class TestExecutionSandboxInProcess:
    """Tests for in-process sandbox (existing behavior preserved)."""

    def test_in_process_run_inline(self):
        """In-process adapter runs inline without thread."""
        sandbox = ExecutionSandbox()
        proposal = ActionProposal(
            intent="noop",
            target="agent:self",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "effect": "no-op", "target": p.target}

        result, replayed = sandbox.run(adapter, proposal)
        assert replayed is False
        assert result["ok"] is True
        assert result["target"] == "agent:self"

    def test_in_process_confines_output(self):
        """Output is confined to JSON-serializable dict."""
        sandbox = ExecutionSandbox()
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return "not a dict"  # Violation

        with pytest.raises(SandboxViolation, match="not a dict"):
            sandbox.run(adapter, proposal)

    def test_in_process_enforces_scope(self):
        """Adapter cannot claim different target than authorized."""
        sandbox = ExecutionSandbox()
        proposal = ActionProposal(
            intent="test",
            target="authorized:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "target": "different:resource"}  # Scope violation

        with pytest.raises(SandboxViolation, match="outside authorized scope"):
            sandbox.run(adapter, proposal)

    def test_in_process_exactly_once(self):
        """Journal provides exactly-once execution across retries."""
        journal = Journal()
        sandbox = ExecutionSandbox(journal=journal)
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        call_count = 0

        def adapter(p):
            nonlocal call_count
            call_count += 1
            return {"ok": True, "count": call_count, "target": p.target}

        # First execution
        result1, replayed1 = sandbox.run(adapter, proposal, idempotency_key="key-1")
        assert replayed1 is False
        assert result1["count"] == 1

        # Second execution with same key should replay
        result2, replayed2 = sandbox.run(adapter, proposal, idempotency_key="key-1")
        assert replayed2 is True
        assert result2["count"] == 1
        assert call_count == 1  # Adapter not called again


class TestExecutionSandboxExternal:
    """Tests for external sandbox (Docker/gVisor) - mocked."""

    def test_docker_sandbox_construction(self):
        """Docker sandbox can be created."""
        policy = SandboxPolicy(use_external=True, sandbox_type="docker")
        sandbox = ExecutionSandbox(policy=policy)
        assert sandbox.policy.sandbox_type == "docker"

    def test_gvisor_sandbox_construction(self):
        """gVisor sandbox can be created."""
        policy = SandboxPolicy(use_external=True, sandbox_type="gvisor")
        sandbox = ExecutionSandbox(policy=policy)
        assert sandbox.policy.sandbox_type == "gvisor"

    def test_unknown_sandbox_type_raises(self):
        """Unknown sandbox type raises violation."""
        policy = SandboxPolicy(use_external=True, sandbox_type="unknown")
        sandbox = ExecutionSandbox(policy=policy)
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "target": p.target}

        with pytest.raises(SandboxViolation, match="Unknown sandbox type"):
            sandbox.run(adapter, proposal)

    @patch("subprocess.run")
    def test_docker_execution_success(self, mock_run):
        """Docker execution returns parsed result on success."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true, "effect": "test", "target": "test:resource"}',
            stderr=""
        )
        policy = SandboxPolicy(use_external=True, sandbox_type="docker", timeout_s=30)
        sandbox = ExecutionSandbox(policy=policy)
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "target": p.target}

        result, replayed = sandbox.run(adapter, proposal)
        assert replayed is False
        assert result["ok"] is True
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_docker_execution_failure(self, mock_run):
        """Docker execution failure raises SandboxViolation."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="container error"
        )
        policy = SandboxPolicy(use_external=True, sandbox_type="docker", timeout_s=30)
        sandbox = ExecutionSandbox(policy=policy)
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "target": p.target}

        with pytest.raises(SandboxViolation, match="Docker execution failed"):
            sandbox.run(adapter, proposal)

    @patch("subprocess.run")
    def test_gvisor_execution_success(self, mock_run):
        """gVisor execution returns parsed result on success."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ok": true, "effect": "test", "target": "test:resource"}',
            stderr=""
        )
        policy = SandboxPolicy(use_external=True, sandbox_type="gvisor", timeout_s=30)
        sandbox = ExecutionSandbox(policy=policy)
        proposal = ActionProposal(
            intent="test",
            target="test:resource",
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

        def adapter(p):
            return {"ok": True, "target": p.target}

        result, replayed = sandbox.run(adapter, proposal)
        assert replayed is False
        assert result["ok"] is True
        mock_run.assert_called_once()


class TestSandboxConfig:
    """Tests for sandbox configuration from YAML."""

    def test_create_from_config_none(self):
        """Creating from None config returns default sandbox."""
        sandbox = create_sandbox_from_config(None)
        assert isinstance(sandbox, ExecutionSandbox)
        assert sandbox.policy.use_external is False

    def test_create_from_missing_file(self):
        """Creating from missing file returns default sandbox."""
        sandbox = create_sandbox_from_config("/nonexistent/path.yaml")
        assert isinstance(sandbox, ExecutionSandbox)
        assert sandbox.policy.use_external is False

    def test_create_from_yaml_file(self, tmp_path):
        """Creating from YAML file parses config."""
        config_file = tmp_path / "sandbox.yaml"
        config_file.write_text("""
sandbox:
  max_output_bytes: 1024
  timeout_s: 10.0
  use_external: true
  type: "docker"
  image: "custom:latest"
""")
        sandbox = create_sandbox_from_config(str(config_file))
        assert sandbox.policy.max_output_bytes == 1024
        assert sandbox.policy.timeout_s == 10.0
        assert sandbox.policy.use_external is True
        assert sandbox.policy.sandbox_type == "docker"
        assert sandbox.policy.sandbox_image == "custom:latest"


class TestSandboxIntegrationWithPEP:
    """Integration tests with PolicyEnforcementPoint."""

    def test_pep_uses_sandbox(self):
        """PEP passes sandbox to enforcement."""
        import secrets

        from maestro.security.enforcement import PolicyEnforcementPoint
        from maestro.security.identity import CapabilityIssuer
        from maestro.security.ledger import Ledger

        key = secrets.token_hex(32)
        issuer = CapabilityIssuer(key=key)
        ledger = Ledger(key=key)

        sandbox = ExecutionSandbox()

        pep = PolicyEnforcementPoint(
            issuer=issuer,
            ledger=ledger,
            evidence_exists=lambda e: True,
            tenant="test",
            adapters={"noop": lambda p: {"ok": True, "effect": "no-op"}},
            sandbox=sandbox,
        )

        assert pep._sandbox is sandbox


if __name__ == "__main__":
    pytest.main([__file__, "-v"])