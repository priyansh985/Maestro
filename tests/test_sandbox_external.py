"""Tests for external sandbox support (BP4)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
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


class TestExternalInvocationContract:
    """Pin the external subprocess invocation contract (mocked, cross-platform).

    No container is spawned here: these tests assert the exact command line and
    the fail-closed behavior of the Docker/gVisor paths so that the Linux
    integration lane (``.github/workflows/linux-integration.yml``) can exercise
    the same contract for real. In-process mode stays the default; every test
    below opts in explicitly with ``use_external=True``.
    """

    @staticmethod
    def _proposal(target: str = "test:resource") -> ActionProposal:
        return ActionProposal(
            intent="test",
            target=target,
            reason="test",
            evidence_ids=("e1",),
            requested_ttl_seconds=300,
        )

    @staticmethod
    def _adapter():
        def adapter(p):
            return {"ok": True, "target": p.target}

        return adapter

    @staticmethod
    def _ok(stdout: str):
        return MagicMock(returncode=0, stdout=stdout, stderr="")

    def _run(self, sandbox_type: str, mock_run, **policy_kwargs):
        policy = SandboxPolicy(
            use_external=True,
            sandbox_type=sandbox_type,
            timeout_s=policy_kwargs.get("timeout_s", 30),
            max_output_bytes=policy_kwargs.get("max_output_bytes", 64 * 1024),
        )
        sandbox = ExecutionSandbox(policy=policy)
        return sandbox.run(self._adapter(), self._proposal())

    @patch("subprocess.run")
    def test_docker_command_confines_network_fs_and_resources(self, mock_run):
        """Docker is launched with no network, read-only fs/mount and resource caps."""
        mock_run.return_value = self._ok('{"ok": true}')
        self._run("docker", mock_run)

        cmd = mock_run.call_args.args[0]
        assert cmd[:2] == ["docker", "run"]
        assert "--network=none" in cmd
        assert "--read-only" in cmd
        assert "--security-opt=no-new-privileges" in cmd
        assert any(flag.startswith("--memory=") for flag in cmd)
        assert any(flag.startswith("--cpus=") for flag in cmd)
        assert any(flag.startswith("--pids-limit=") for flag in cmd)
        assert len([a for a in cmd if a.endswith(":/input.json:ro")]) == 1

    @patch("subprocess.run")
    def test_gvisor_invokes_runsc_with_no_network(self, mock_run):
        """gVisor mode invokes the runsc runtime, not docker, with no network."""
        mock_run.return_value = self._ok('{"ok": true}')
        self._run("gvisor", mock_run)

        cmd = mock_run.call_args.args[0]
        assert cmd[:2] == ["runsc", "run"]
        assert "--network=none" in cmd
        assert any(a.endswith(":/input.json:ro") for a in cmd)

    @patch("subprocess.run")
    def test_missing_docker_runtime_fails_closed(self, mock_run):
        """A missing docker binary is a SandboxViolation, not a raw OSError."""
        mock_run.side_effect = FileNotFoundError("docker")
        with pytest.raises(SandboxViolation) as exc:
            self._run("docker", mock_run)
        assert "runtime not found" in str(exc.value)
        assert "docker" in str(exc.value)

    @patch("subprocess.run")
    def test_missing_gvisor_runtime_fails_closed(self, mock_run):
        """A missing runsc binary names the actual runtime in the error."""
        mock_run.side_effect = FileNotFoundError("runsc")
        with pytest.raises(SandboxViolation) as exc:
            self._run("gvisor", mock_run)
        assert "runtime not found" in str(exc.value)
        assert "runsc" in str(exc.value)

    @patch("subprocess.run")
    def test_external_timeout_fails_closed(self, mock_run):
        """A timed-out guest fails the action closed with a clear violation."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=30)
        with pytest.raises(SandboxViolation, match="timed out"):
            self._run("docker", mock_run)

    @patch("subprocess.run")
    def test_external_output_byte_cap_enforced(self, mock_run):
        """The guest's stdout is confined to the configured byte budget."""
        mock_run.return_value = self._ok(json.dumps({"ok": True, "blob": "x" * 200}))
        with pytest.raises(SandboxViolation, match="exceeds.*byte cap"):
            self._run("docker", mock_run, max_output_bytes=64)

    @patch("subprocess.run")
    def test_external_output_scope_enforced(self, mock_run):
        """A guest claiming another target cannot bypass scope confinement."""
        mock_run.return_value = self._ok('{"ok": true, "target": "other:resource"}')
        with pytest.raises(SandboxViolation, match="outside authorized scope"):
            self._run("docker", mock_run)

    @patch("subprocess.run")
    def test_non_json_output_fails_closed(self, mock_run):
        """Unparseable guest output fails closed instead of leaking a JSON error."""
        mock_run.return_value = self._ok("not json")
        with pytest.raises(SandboxViolation, match="non-JSON"):
            self._run("docker", mock_run)

    @patch("subprocess.run")
    def test_timeout_is_forwarded_to_subprocess(self, mock_run):
        """The policy timeout bounds the guest's wall-clock execution."""
        mock_run.return_value = self._ok('{"ok": true}')
        self._run("docker", mock_run, timeout_s=7)
        assert mock_run.call_args.kwargs["timeout"] == 7

    @patch("subprocess.run")
    def test_input_file_is_removed_after_run(self, mock_run):
        """The temp input file is cleaned up on both success and failure paths."""
        mock_run.return_value = self._ok('{"ok": true}')
        self._run("docker", mock_run)
        cmd = mock_run.call_args.args[0]
        mount = next(a for a in cmd if a.endswith(":/input.json:ro"))
        input_path = mount.split(":/input.json:ro")[0]
        assert not os.path.exists(input_path)


@pytest.mark.skipif(
    os.environ.get("MAESTRO_SANDBOX_REAL") != "1",
    reason="real-runtime checks run only in the Linux lane (MAESTRO_SANDBOX_REAL=1)",
)
class TestRealRuntimeContract:
    """The only un-mocked tests, gated on MAESTRO_SANDBOX_REAL=1.

    These are skipped in the default offline/Windows path. The Linux
    integration lane sets the flag and aborts if any of them is skipped, so a
    mock fallback can never masquerade as real containment evidence there.
    The gVisor gate is runtime-availability only; a real `runsc run` guest is a
    documented follow-up, not a claim made by this first step.
    """

    def test_real_docker_isolation_smoke(self):
        assert shutil.which("docker"), "docker is required in the real-sandbox lane"
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network=none", "--read-only",
                "python:3.11-slim", "python", "-c", "print('maestro-sandbox-smoke-ok')",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "maestro-sandbox-smoke-ok"

    def test_real_gvisor_runtime_available(self):
        assert shutil.which("runsc"), "runsc is required in the real-sandbox lane"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])