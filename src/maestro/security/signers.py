"""Signer protocol + registry for policy-bundle approval identities (v1.1 item 5).

This module is the seam that lets the two-person policy-bundle approval rule
bind to *external* identities (OIDC/KMS-backed keys per approver) instead of a
single shared HMAC key. The :class:`Signer` protocol is the contract; the
default :class:`HMACSigner` preserves the legacy shared-key behaviour, and
:class:`ExternalSigner` is the documented stub subclasses plug into.

Production OIDC/KMS support is NOT claimed here -- :class:`ExternalSigner`
raises :class:`NotImplementedError` naming the seam so callers cannot mistake
the stub for a live backend.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    """Contract for an identity that can sign and verify a bundle digest."""

    def identity(self) -> str:
        """Stable identity string for this signer (e.g. an approver id)."""
        ...

    def sign(self, digest: str) -> str:
        """Return a signature over ``digest``."""
        ...

    def verify(self, digest: str, signature: str) -> bool:
        """Return True iff ``signature`` is valid for ``digest``."""
        ...


def _coerce_key(key: object) -> bytes:
    if isinstance(key, bytes | bytearray):
        return bytes(key)
    if isinstance(key, str):
        return key.encode("utf-8")
    raise TypeError("signing key must be bytes or str")


class HMACSigner:
    """Default signer: HMAC-SHA256 over a shared key, identity from an id string."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        identity: object | None = kwargs.pop("identity", None)
        if identity is None:
            identity = kwargs.pop("identity_id", None)
        if identity is None:
            identity = kwargs.pop("id", None)
        if identity is None:
            identity = kwargs.pop("signer_id", None)
        if identity is None:
            identity = kwargs.pop("key_id", None)

        key: object | None = kwargs.pop("key", None)
        if key is None:
            key = kwargs.pop("secret", None)
        if key is None:
            key = kwargs.pop("private_key", None)
        if key is None:
            key = kwargs.pop("signing_key", None)

        if args:
            if len(args) == 1:
                if identity is None and key is None:
                    if isinstance(args[0], str):
                        identity = args[0]
                    else:
                        key = args[0]
                elif identity is None:
                    identity = args[0]
                elif key is None:
                    key = args[0]
            elif len(args) >= 2:
                first, second = args[0], args[1]
                if identity is None and key is None:
                    if isinstance(first, bytes | bytearray) and isinstance(second, str):
                        key = first
                        identity = second
                    else:
                        identity = first
                        key = second
                else:
                    if identity is None:
                        identity = first
                    if key is None:
                        key = second

        if identity is None or not str(identity).strip():
            raise ValueError("HMACSigner requires a non-empty identity")
        if key is None:
            raise ValueError("HMACSigner requires a signing key")

        self._identity = str(identity).strip()
        self._key = _coerce_key(key)

    def identity(self) -> str:
        return self._identity

    def sign(self, digest: str) -> str:
        return hmac.new(self._key, digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, digest: str, signature: str) -> bool:
        expected = hmac.new(self._key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class ExternalSigner:
    """Documented seam for OIDC/KMS-backed per-approver signers.

    Subclasses override :meth:`identity`, :meth:`sign` and :meth:`verify` to
    bind to a real identity provider or key-management service. The base
    implementation deliberately raises :class:`NotImplementedError` so the
    seam cannot be mistaken for production support.
    """

    def __init__(self, identity: str | None = None, **kwargs: object) -> None:
        ident: object = identity
        if ident is None:
            ident = kwargs.get("identity_id", kwargs.get("id", kwargs.get("signer_id")))
        self._identity = "" if ident is None else str(ident).strip()

    def identity(self) -> str:
        if not self._identity:
            raise NotImplementedError(
                "external signer seam (OIDC/KMS per approver) is not implemented: "
                "identity is not configured"
            )
        return self._identity

    def sign(self, digest: str) -> str:
        raise NotImplementedError(
            "external signer seam (OIDC/KMS per approver) is not implemented; "
            "subclass ExternalSigner and wire an OIDC/KMS backend"
        )

    def verify(self, digest: str, signature: str) -> bool:
        raise NotImplementedError(
            "external signer seam (OIDC/KMS per approver) is not implemented; "
            "subclass ExternalSigner and wire an OIDC/KMS backend"
        )


class SignerRegistry:
    """Maps signer identity -> :class:`Signer`."""

    def __init__(self) -> None:
        self._signers: dict[str, Signer] = {}

    def register(self, *args: object, **kwargs: object) -> None:
        signer: object | None = None
        identity: object | None = None
        if len(args) == 1 and "identity" not in kwargs and "signer" not in kwargs:
            signer = args[0]
            ident_fn = getattr(signer, "identity", None)
            if callable(ident_fn):
                try:
                    identity = ident_fn()
                except Exception:
                    identity = None
        elif len(args) >= 2:
            identity = args[0]
            signer = args[1]
        else:
            identity = kwargs.get("identity", kwargs.get("identity_id"))
            signer = kwargs.get("signer", kwargs.get("signer_instance"))

        if signer is None:
            raise ValueError("SignerRegistry.register requires a Signer")
        if identity is None:
            ident_fn = getattr(signer, "identity", None)
            if callable(ident_fn):
                try:
                    identity = ident_fn()
                except Exception as exc:
                    raise ValueError("signer has no identity") from exc
        if identity is None or not str(identity).strip():
            raise ValueError("signer identity must be non-empty")
        self._signers[str(identity).strip()] = signer  # type: ignore[assignment]

    def get(self, identity: object) -> Signer | None:
        key = identity.strip() if isinstance(identity, str) else identity
        return self._signers.get(key)  # type: ignore[call-overload]

    def identities(self) -> list[str]:
        return sorted(self._signers.keys())


def two_person_rule_ok(proposer: str, approver: str) -> bool:
    """True iff proposer and approver are distinct, non-empty identities."""
    p = "" if proposer is None else str(proposer).strip()
    a = "" if approver is None else str(approver).strip()
    return bool(p) and bool(a) and p != a