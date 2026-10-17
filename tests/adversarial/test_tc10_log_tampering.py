"""TC10: Log Tampering Test.

Tests that hash-chain detects tampering and alerts.
"""
from __future__ import annotations

import secrets

import pytest

from maestro.security.ledger import Ledger


class TestTC10LogTampering:
    """TC10 - Log tampering must be detected by hash chain."""

    @pytest.fixture
    def ledger(self):
        key = secrets.token_hex(32)
        return Ledger(key=key)

    def test_append_event(self, ledger):
        """Appending an event creates a valid chain."""
        event = ledger.append(
            event_type="test",
            actor_identity="agent:test",
            decision="allow",
            input_hash="hash123",
        )
        assert event.event_id.startswith("evt-")
        assert event.prev_event_hash == "0" * 64  # Genesis
        assert event.event_hash != ""
        assert event.hmac != ""

    def test_chain_integrity_verified(self, ledger):
        """Chain integrity verification returns -1 for intact chain."""
        ledger.append(event_type="event1", actor_identity="a", decision="allow", input_hash="h1")
        ledger.append(event_type="event2", actor_identity="b", decision="deny", input_hash="h2")
        ledger.append(event_type="event3", actor_identity="c", decision="allow", input_hash="h3")
        
        assert ledger.verify_chain() == -1  # Intact

    def test_tampering_detected_modified_event(self, ledger):
        """Modifying an event breaks the chain."""
        ledger.append(event_type="event1", actor_identity="a", decision="allow", input_hash="h1")
        ledger.append(event_type="event2", actor_identity="b", decision="deny", input_hash="h2")
        
        # Tamper with the first event
        ledger._events[0] = ledger._events[0].__class__(
            **{**ledger._events[0].__dict__, "decision": "tampered"}
        )
        
        # Chain verification should detect tampering
        broken_index = ledger.verify_chain()
        assert broken_index != -1
        assert broken_index == 0 or broken_index == 1

    def test_tampering_detected_deleted_event(self, ledger):
        """Deleting an event breaks the chain."""
        ledger.append(event_type="event1", actor_identity="a", decision="allow", input_hash="h1")
        ledger.append(event_type="event2", actor_identity="b", decision="deny", input_hash="h2")
        ledger.append(event_type="event3", actor_identity="c", decision="allow", input_hash="h3")
        
        # Delete middle event
        del ledger._events[1]
        
        broken_index = ledger.verify_chain()
        assert broken_index != -1

    def test_tampering_detected_inserted_event(self, ledger):
        """Inserting an event breaks the chain."""
        ledger.append(event_type="event1", actor_identity="a", decision="allow", input_hash="h1")
        ledger.append(event_type="event2", actor_identity="b", decision="deny", input_hash="h2")
        
        # Insert a fake event
        import time

        from maestro.security.ledger import AuditEvent
        fake_event = AuditEvent(
            event_id="evt-fake",
            timestamp_utc=time.time(),
            event_type="fake",
            actor_identity="attacker",
            decision="allow",
            input_hash="fake",
            policy_digest="",
            risk_before=0.0,
            risk_after=0.0,
            prev_event_hash=ledger._events[0].event_hash,
            event_hash="fake_hash",
            hmac="fake_hmac",
        )
        ledger._events.insert(1, fake_event)
        
        broken_index = ledger.verify_chain()
        assert broken_index != -1

    def test_hmac_forgery_detected(self, ledger):
        """Forging HMAC without key is detected."""
        ledger.append(event_type="event1", actor_identity="a", decision="allow", input_hash="h1")
        
        # Tamper with HMAC
        ledger._events[0] = ledger._events[0].__class__(
            **{**ledger._events[0].__dict__, "hmac": "forged_hmac"}
        )
        
        broken_index = ledger.verify_chain()
        assert broken_index != -1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])