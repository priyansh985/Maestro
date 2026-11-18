"""Tests for the Signer protocol seam (v1.1 item 5)."""
from __future__ import annotations

import pytest

from maestro.security.policy_bundle import PolicyBundle
from maestro.security.policy_bundle_signed import (
    PolicyBundleSignature,
    SignedPolicyBundle,
)
from maestro.security.signers import (
    ExternalSigner,
    HMACSigner,
    Signer,
    SignerRegistry,
    two_person_rule_ok,
)


def _digest() -> str:
    return "sha256:deadbeef"


def test_hmac_signer_round_trip():
    signer = HMACSigner("alice", "secret-key")
    digest = "policy-digest-123"
    sig = signer.sign(digest)
    assert signer.verify(digest, sig) is True
    assert signer.identity() == "alice"
    # protocol conformance
    assert isinstance(signer, Signer)


def test_hmac_signer_wrong_key_fails():
    a = HMACSigner("alice", "key-a")
    b = HMACSigner("alice", "key-b")
    digest = "policy-digest-123"
    sig = a.sign(digest)
    assert b.verify(digest, sig) is False


def test_external_signer_raises_not_implemented():
    signer = ExternalSigner("bob")
    with pytest.raises(NotImplementedError, match="OIDC/KMS"):
        signer.sign("digest")
    with pytest.raises(NotImplementedError, match="OIDC/KMS"):
        signer.verify("digest", "sig")
    # base identity may be configured but sign/verify still raise
    assert signer.identity() == "bob"


def test_external_signer_unconfigured_identity_raises():
    signer = ExternalSigner()
    with pytest.raises(NotImplementedError):
        signer.identity()


def test_registry_register_get_identities():
    reg = SignerRegistry()
    s1 = HMACSigner("alice", "k1")
    s2 = HMACSigner("bob", "k2")
    reg.register(s1)
    reg.register("carol", s2)  # identity override form
    assert reg.get("alice") is s1
    assert reg.get("carol") is s2
    assert reg.get("missing") is None
    assert set(reg.identities()) == {"alice", "carol"}


def test_two_person_rule():
    assert two_person_rule_ok("alice", "bob") is True
    assert two_person_rule_ok("alice", "alice") is False
    assert two_person_rule_ok("", "bob") is False
    assert two_person_rule_ok("alice", "") is False
    assert two_person_rule_ok("alice", "   ") is False
    assert two_person_rule_ok("   ", "bob") is False


def test_tampered_digest_fails():
    signer = HMACSigner("alice", "secret-key")
    digest = "original-digest"
    sig = signer.sign(digest)
    assert signer.verify("tampered-digest", sig) is False


def test_registry_based_verification():
    reg = SignerRegistry()
    signer = HMACSigner("alice", "secret-key")
    reg.register(signer)
    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"])
    digest = bundle.digest()
    signature = signer.sign(digest)
    signed = SignedPolicyBundle(
        bundle,
        [PolicyBundleSignature(signature=signature, signed_by="alice", key_id="alice")],
        requires_signatures=1,
        signers=reg,
    )
    assert signed.verify_signatures() is True

    # tampered bundle fails
    changed = PolicyBundle.create(version=2, allowed_intents=["code_write"])
    tampered = SignedPolicyBundle(
        changed,
        [PolicyBundleSignature(signature=signature, signed_by="alice", key_id="alice")],
        requires_signatures=1,
        signers=reg,
    )
    assert tampered.verify_signatures() is False

    # wrong signer (not in registry) fails
    signed2 = SignedPolicyBundle(
        bundle,
        [PolicyBundleSignature(signature=signature, signed_by="mallory", key_id="mallory")],
        requires_signatures=1,
        signers=reg,
    )
    assert signed2.verify_signatures() is False


def test_legacy_path_still_works():
    bundle = PolicyBundle.create(version=1, allowed_intents=["noop"])
    signer = HMACSigner("alice", "synthetic-private-secret")
    signature = PolicyBundleSignature(
        signature=signer.sign(bundle.digest()),
        signed_by="alice",
        key_id="alice",
    )
    signed = SignedPolicyBundle(bundle, [signature], requires_signatures=1)
    assert signed.verify_signatures(trusted_keys={"alice": "synthetic-private-secret"}) is True
    assert signed.verify_signatures(trusted_keys={"alice": "wrong"}) is False
    assert signed.verify_signatures() is False