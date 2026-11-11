"""Regressions for enterprise helper contracts; not deployment certification."""
from __future__ import annotations

import json

import pytest

from maestro.compliance.export import ComplianceExporter
from maestro.security.ledger import Ledger
from maestro.security.policy_bundle import PolicyBundle
from maestro.security.policy_bundle_signed import (
    PolicySigner,
    SignedPolicyBundle,
    SignedPolicyRegistry,
    VersionPinner,
)


def test_nonempty_ledger_exports_its_actual_event_timestamp():
    ledger = Ledger(key=b"test-key")
    event = ledger.append(event_type="example", actor_identity="test", decision="denied", input_hash="x")
    report = ComplianceExporter(ledger, b"test-key").generate_report()
    evidence = [e for e in report.evidence if e.evidence_type == "ledger"]
    assert len(evidence) == 1
    assert evidence[0].timestamp == event.timestamp_utc
    assert report.ledger_summary["total_events"] == 1
    assert report.test_results.get("status") == "not_assessed"
    assert "passed" not in report.test_results


def test_policy_signature_uses_configured_trust_without_serializing_secret():
    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"])
    signature = PolicySigner("synthetic-private-secret", "alice").sign(bundle)
    signed = SignedPolicyBundle(bundle, [signature], requires_signatures=1)
    assert "synthetic-private-secret" not in json.dumps(signed.to_dict())
    assert signed.verify_signatures() is False
    assert signed.verify_signatures(trusted_keys={"alice": "wrong-key"}) is False
    assert signed.verify_signatures(trusted_keys={"alice": "synthetic-private-secret"}) is True
    changed = PolicyBundle.create(version=2, allowed_intents=["code_write"])
    assert SignedPolicyBundle(changed, [signature], requires_signatures=1).verify_signatures(
        trusted_keys={"alice": "synthetic-private-secret"}) is False


def test_duplicate_signer_does_not_satisfy_two_person_requirement():
    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"])
    signature = PolicySigner("test-key", "alice").sign(bundle)
    signed = SignedPolicyBundle(bundle, [signature, signature], requires_signatures=2)
    assert signed.verify_signatures(trusted_keys={"alice": "test-key"}) is False


def test_unimplemented_external_registry_is_explicitly_unavailable():
    with pytest.raises(NotImplementedError, match="governance"):
        SignedPolicyRegistry()


def test_version_pin_uses_real_bundle_digest(tmp_path):
    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"])
    path = tmp_path / "pins.json"
    VersionPinner(path).pin("1", bundle, "test")
    assert VersionPinner(path).get_pin("1").bundle_hash == bundle.digest()


def test_unimplemented_replication_cannot_report_a_rewritten_chain_as_replicated():
    from maestro.dr.disaster_recovery import DRConfig, ReplicationManager
    primary, standby = Ledger(key=b"test-key"), Ledger(key=b"test-key")
    primary.append(event_type="test", actor_identity="test", decision="observe", input_hash="x")
    manager = ReplicationManager(primary, standby, DRConfig())
    with pytest.raises(NotImplementedError, match="replication"):
        manager.replicate_once()
    assert len(standby) == 0
