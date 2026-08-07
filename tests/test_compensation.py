"""Tests for compensation framework (BP4)."""
from __future__ import annotations

import pytest

from maestro.security.action import parse_proposal
from maestro.security.compensation import (
    COMPENSATION_REGISTRY,
    CompensationAction,
    compensate,
    get_compensation,
    list_compensations,
    register_compensation,
    validate_compensation_registry,
)


class TestCompensationRegistry:
    """Tests for the compensation registry."""

    def test_all_capability_required_have_compensation(self):
        """Every CAPABILITY_REQUIRED_ACTION should have a compensation."""
        # The validation checks intents that map to capability-required action classes
        # against the compensation registry (which uses original intents as keys)
        missing = validate_compensation_registry()
        # Note: compensation intents (like restore_credentials) are not the same as
        # original intents (like rotate_credentials). The validation checks original intents.
        assert missing == [], f"Missing compensations for: {missing}"

    def test_known_compensations_exist(self):
        """Key compensations are registered."""
        assert "block_source_ip" in COMPENSATION_REGISTRY
        assert "rate_limit_source" in COMPENSATION_REGISTRY
        assert "rotate_credentials" in COMPENSATION_REGISTRY
        assert "run_containment_script" in COMPENSATION_REGISTRY
        assert "code_git_push" in COMPENSATION_REGISTRY
        assert "code_open_pr" in COMPENSATION_REGISTRY
        assert "quarantine_memory_record" in COMPENSATION_REGISTRY
        assert "promote_memory" in COMPENSATION_REGISTRY
        assert "alert_operator" in COMPENSATION_REGISTRY

    def test_get_compensation(self):
        """Get compensation for known intent."""
        comp = get_compensation("block_source_ip")
        assert comp is not None
        assert comp.original_intent == "block_source_ip"
        assert comp.compensation_intent == "unblock_source_ip"

    def test_get_compensation_unknown(self):
        """Unknown intent returns None."""
        comp = get_compensation("nonexistent_intent")
        assert comp is None

    def test_register_compensation(self):
        """Can register new compensation."""
        new_comp = CompensationAction(
            original_intent="custom_action",
            compensation_intent="custom_undo",
            make_args=lambda p, r: {"key": "value"},
            description="Custom compensation",
        )
        register_compensation(new_comp)
        assert get_compensation("custom_action") is not None
        # Cleanup
        COMPENSATION_REGISTRY.pop("custom_action", None)

    def test_list_compensations(self):
        """List all compensations."""
        comps = list_compensations()
        assert len(comps) >= 9  # At least the core ones
        assert all(isinstance(c, CompensationAction) for c in comps)


class TestCompensationArgs:
    """Tests for compensation argument generation."""

    def test_block_source_ip_compensation_args(self):
        """Compensation args for block_source_ip."""
        comp = get_compensation("block_source_ip")
        proposal = parse_proposal(
            '{"intent": "block_source_ip", "target": "192.168.1.1", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {}
        
        args = comp.make_args(proposal, execution_result)
        assert args["ip"] == "192.168.1.1"
        assert "Compensate block_source_ip" in args["reason"]

    def test_code_git_push_compensation_args(self):
        """Compensation args for code_git_push include commit SHA."""
        comp = get_compensation("code_git_push")
        proposal = parse_proposal(
            '{"intent": "code_git_push", "target": "code:repo:test", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {"commit_sha": "abc123", "branch": "main"}
        
        args = comp.make_args(proposal, execution_result)
        assert args["commit_sha"] == "abc123"
        assert args["branch"] == "main"

    def test_code_open_pr_compensation_args(self):
        """Compensation args for code_open_pr include PR number."""
        comp = get_compensation("code_open_pr")
        proposal = parse_proposal(
            '{"intent": "code_open_pr", "target": "code:repo:test", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {"pr_number": 42}
        
        args = comp.make_args(proposal, execution_result)
        assert args["pr_number"] == 42

    def test_rotate_credentials_requires_approval(self):
        """Rotate credentials compensation requires approval."""
        comp = get_compensation("rotate_credentials")
        assert comp.requires_approval is True

    def test_run_containment_script_requires_approval(self):
        """Containment script compensation requires approval."""
        comp = get_compensation("run_containment_script")
        assert comp.requires_approval is True


class TestCompensateFunction:
    """Tests for the compensate() function."""

    def test_compensate_no_issuer_returns_proposal(self):
        """Without issuer/ledger, returns compensation proposal."""
        proposal = parse_proposal(
            '{"intent": "block_source_ip", "target": "192.168.1.1", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {}
        
        result = compensate(proposal, execution_result)
        
        assert result["status"] == "compensation_proposal_generated"
        assert "compensation_proposal" in result
        assert result["compensation_proposal"]["intent"] == "unblock_source_ip"

    def test_compensate_unknown_intent(self):
        """Unknown intent returns no_compensation_defined."""
        # Create a proposal for an intent that has no compensation registered
        # but is in the allow-list (so parse_proposal succeeds)
        proposal = parse_proposal(
            '{"intent": "noop", "target": "agent:self", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {}
        
        result = compensate(proposal, execution_result)
        
        assert result["status"] == "no_compensation_defined"

    def test_compensate_with_config(self):
        """Compensation config is merged into args."""
        proposal = parse_proposal(
            '{"intent": "rotate_credentials", "target": "cred:123", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {}
        config = {"backup_id": "backup-456"}
        
        result = compensate(proposal, execution_result, compensation_config=config)
        
        assert result["status"] == "compensation_proposal_generated"
        assert result["compensation_args"]["backup_id"] == "backup-456"


class TestCompensationIntegration:
    """Integration tests with full enforcement stack (requires issuer/ledger)."""

    def test_compensate_with_issuer_and_ledger(self):
        """Full compensation execution through PEP."""
        import secrets

        from maestro.security.identity import CapabilityIssuer
        from maestro.security.ledger import Ledger
        
        key = secrets.token_hex(32)
        issuer = CapabilityIssuer(key=key)
        ledger = Ledger(key=key)
        
        proposal = parse_proposal(
            '{"intent": "block_source_ip", "target": "192.168.1.1", "reason": "test", '
            '"evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        )
        execution_result = {}
        
        result = compensate(
            proposal, 
            execution_result, 
            issuer=issuer, 
            ledger=ledger,
            tenant="test",
        )
        
        assert result["status"] == "compensated"
        assert result["compensation_intent"] == "unblock_source_ip"
        assert "compensation_event_id" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])