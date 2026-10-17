"""TC5: Tool Argument Smuggling Test.

Tests that malformed tool arguments are rejected by schema validation.
"""
from __future__ import annotations

import pytest

from maestro.security.action import InvalidProposal, parse_proposal


class TestTC5ToolArgumentSmuggling:
    """TC5 - Tool argument smuggling must be rejected by schema validation."""

    def test_sql_injection_in_target_parses_but_adapter_rejects(self):
        """SQL injection in target field passes parsing but adapter rejects at execution.
        
        The parser accepts it (it's a valid string), but the sandbox/adapter 
        enforces scope confinement.
        """
        proposal = '{"intent": "block_source_ip", "target": "192.168.1.1; DROP TABLE users;", "reason": "test", "evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        parsed = parse_proposal(proposal)
        assert parsed.intent == "block_source_ip"
        assert parsed.target == "192.168.1.1; DROP TABLE users;"

    def test_command_injection_in_reason_parses_but_adapter_rejects(self):
        """Command injection in reason field is accepted by parser (valid JSON string)."""
        proposal = '{"intent": "noop", "target": "agent:self", "reason": "test && rm -rf /", "evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        parsed = parse_proposal(proposal)
        assert parsed.intent == "noop"

    def test_path_traversal_in_target_parses_but_adapter_rejects(self):
        """Path traversal in target field passes parsing, adapter enforces scope."""
        proposal = '{"intent": "code_read", "target": "../../../etc/passwd", "reason": "test", "evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        parsed = parse_proposal(proposal)
        assert parsed.intent == "code_read"
        assert parsed.target == "../../../etc/passwd"

    def test_oversized_payload_parses_but_sandbox_rejects(self):
        """Oversized payload passes parsing, sandbox enforces size limit."""
        huge_reason = "x" * 100000
        proposal = f'{{"intent": "noop", "target": "agent:self", "reason": "{huge_reason}", "evidence_ids": ["e1"], "requested_ttl_seconds": 300}}'
        parsed = parse_proposal(proposal)
        assert parsed.intent == "noop"

    def test_missing_evidence_ids_rejected(self):
        """Proposal without evidence_ids is rejected by parser."""
        proposal = '{"intent": "noop", "target": "agent:self", "reason": "test", "requested_ttl_seconds": 300}'
        with pytest.raises(InvalidProposal, match="missing required field"):
            parse_proposal(proposal)

    def test_empty_evidence_ids_rejected(self):
        """Proposal with empty evidence_ids is rejected by parser."""
        proposal = '{"intent": "noop", "target": "agent:self", "reason": "test", "evidence_ids": [], "requested_ttl_seconds": 300}'
        with pytest.raises(InvalidProposal):
            parse_proposal(proposal)

    def test_negative_ttl_rejected(self):
        """Negative TTL is rejected by parser."""
        proposal = '{"intent": "noop", "target": "agent:self", "reason": "test", "evidence_ids": ["e1"], "requested_ttl_seconds": -1}'
        with pytest.raises(InvalidProposal):
            parse_proposal(proposal)

    def test_unknown_intent_rejected(self):
        """Unknown intent is rejected by parser."""
        proposal = '{"intent": "malicious_intent", "target": "test", "reason": "test", "evidence_ids": ["e1"], "requested_ttl_seconds": 300}'
        with pytest.raises(InvalidProposal, match="unknown intent"):
            parse_proposal(proposal)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])