"""Tests for release gate framework (BP7)."""
from __future__ import annotations

import os
import tempfile

import pytest

from maestro.security.release_gate import (
    DEFAULT_GATES,
    Gate,
    GateBundle,
    GateBundleResult,
    GateRegistry,
    ReleaseGateEvaluator,
    create_gate_bundle,
)


class TestGate:
    """Tests for Gate dataclass."""

    def test_gate_creation(self):
        """Gate can be created with required fields."""
        gate = Gate(name="test_gate", description="Test gate", threshold=0.8, required=True)
        assert gate.name == "test_gate"
        assert gate.description == "Test gate"
        assert gate.threshold == 0.8
        assert gate.required is True

    def test_gate_optional_required(self):
        """Gate required field defaults to True."""
        gate = Gate(name="test_gate", description="Test gate", threshold=0.8)
        assert gate.required is True


class TestGateBundle:
    """Tests for GateBundle dataclass."""

    def test_bundle_creation(self):
        """GateBundle can be created with required fields."""
        gates = (Gate("gate1", "desc", 0.8), Gate("gate2", "desc", 0.9))
        bundle = GateBundle(
            version="1.0.0",
            agent_spec_hash="abc123",
            gates=gates,
        )
        assert bundle.version == "1.0.0"
        assert bundle.agent_spec_hash == "abc123"
        assert len(bundle.gates) == 2

    def test_bundle_thresholds_auto_populated(self):
        """Thresholds dict is auto-populated from gates."""
        gates = (Gate("gate1", "desc", 0.8), Gate("gate2", "desc", 0.9))
        bundle = GateBundle(
            version="1.0.0",
            agent_spec_hash="abc123",
            gates=gates,
        )
        assert bundle.thresholds == {"gate1": 0.8, "gate2": 0.9}


class TestGateRegistry:
    """Tests for GateRegistry."""

    def test_registry_register_and_get(self):
        """Register and retrieve a bundle."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
            )
            registered = registry.register(bundle)
            assert registered.version == "1.0.0"
            
            retrieved = registry.get("1.0.0")
            assert retrieved is not None
            assert retrieved.version == "1.0.0"
        finally:
            os.unlink(temp_path)

    def test_registry_duplicate_version_raises(self):
        """Registering duplicate version raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
            )
            registry.register(bundle)
            
            with pytest.raises(ValueError, match="already exists"):
                registry.register(bundle)
        finally:
            os.unlink(temp_path)

    def test_registry_activate(self):
        """Activating a bundle sets it as active."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
            )
            registry.register(bundle)
            registry.activate("1.0.0")
            
            active = registry.active()
            assert active is not None
            assert active.version == "1.0.0"
        finally:
            os.unlink(temp_path)

    def test_registry_activate_nonexistent_raises(self):
        """Activating nonexistent version raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            with pytest.raises(ValueError, match="not found"):
                registry.activate("nonexistent")
        finally:
            os.unlink(temp_path)

    def test_registry_activate_expired_raises(self):
        """Activating expired bundle raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
                expires_at=1.0,  # Expired long ago
            )
            registry.register(bundle)
            
            with pytest.raises(ValueError, match="expired"):
                registry.activate("1.0.0")
        finally:
            os.unlink(temp_path)

    def test_registry_persistence(self):
        """Registry persists bundles across instances."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry1 = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
            )
            registry1.register(bundle)
            registry1.activate("1.0.0")
            
            # New instance should load existing data
            registry2 = GateRegistry(temp_path)
            active = registry2.active()
            assert active is not None
            assert active.version == "1.0.0"
        finally:
            os.unlink(temp_path)


class TestCreateGateBundle:
    """Tests for create_gate_bundle function."""

    def test_create_gate_bundle_signed(self):
        """Created bundle has signature."""
        gates = [Gate("test_gate", "Test gate", 0.8)]
        bundle = create_gate_bundle(
            version="1.0.0",
            agent_spec_hash="spec123",
            gates=gates,
            approver1="alice",
            approver2="bob",
            signing_key=b"test-key",
        )
        assert bundle.signature != ""
        assert bundle.signed_by == ("alice", "bob")

    def test_create_gate_bundle_no_key(self):
        """Created bundle works without explicit signing key."""
        gates = [Gate("test_gate", "Test gate", 0.8)]
        bundle = create_gate_bundle(
            version="1.0.0",
            agent_spec_hash="spec123",
            gates=gates,
            approver1="alice",
            approver2="bob",
        )
        assert bundle.signature != ""


class TestReleaseGateEvaluator:
    """Tests for ReleaseGateEvaluator."""

    def test_evaluate_returns_result(self):
        """Evaluator returns GateBundleResult."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            gates = (Gate("test_gate", "Test gate", 0.8),)
            bundle = GateBundle(
                version="1.0.0",
                agent_spec_hash="spec123",
                gates=gates,
            )
            registry.register(bundle)
            registry.activate("1.0.0")
            
            evaluator = ReleaseGateEvaluator(registry)
            result = evaluator.evaluate(agent_spec=None)
            
            assert isinstance(result, GateBundleResult)
            assert result.bundle_version == "1.0.0"
            assert len(result.gate_results) == 1
        finally:
            os.unlink(temp_path)

    def test_evaluate_no_active_bundle_raises(self):
        """Evaluating with no active bundle raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            temp_path = f.name
        try:
            registry = GateRegistry(temp_path)
            evaluator = ReleaseGateEvaluator(registry)
            
            with pytest.raises(ValueError, match="No active gate bundle"):
                evaluator.evaluate(agent_spec=None)
        finally:
            os.unlink(temp_path)


class TestDefaultGates:
    """Tests for DEFAULT_GATES."""

    def test_default_gates_exist(self):
        """Default gates are defined."""
        assert len(DEFAULT_GATES) >= 5
        gate_names = {g.name for g in DEFAULT_GATES}
        assert "test_suite_pass" in gate_names
        assert "citation_grounding" in gate_names
        assert "safety_envelope" in gate_names
        assert "ledger_integrity" in gate_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])