"""Workload identity and scoped capability tokens (Enforcement Plane).

Implements the research design axiom that *the agent* is not a sufficient
principal: every action carries an attributable workload identity and is
authorized by a **scoped, short-lived, signed capability** — never by model
confidence alone. This is the mechanism that defeats the confused-deputy
problem (a low-trust input may influence a planner, but it cannot inherit the
authority of the firewall administrator).

A :class:`CapabilityToken` is an HMAC-signed claim set binding:

* ``subject``              — the workload instance the capability is issued to.
* ``capability``           — the single action class it authorizes (``cap:...``).
* ``resource_constraint``  — the resource the action may touch.
* ``tenant``               — the tenant boundary the action stays within.
* ``delegation_depth``     — how many delegations deep this token is.
* ``issued_at`` / ``expires_at`` — short TTL; expired tokens fail closed.

Signing uses ``hmac.compare_digest`` over a canonical JSON encoding, so tokens
are tamper-evident and forgery-resistant given a protected key. The key comes
from ``MAESTRO_SIGNING_KEY`` in production; tests inject a fixed key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field

SIGNING_KEY_ENV = "MAESTRO_SIGNING_KEY"
#: Hard cap on delegation chain length (L7 cascading-delegation control).
MAX_DELEGATION_DEPTH = 3


class CapabilityError(Exception):
    """Raised when a capability is missing, malformed, expired, or out of scope."""


def _load_key(key: bytes | str | None) -> bytes:
    if key is None:
        key = os.environ.get(SIGNING_KEY_ENV, "")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise CapabilityError(
            f"no signing key: pass key=... or set {SIGNING_KEY_ENV}")
    return key


@dataclass(frozen=True)
class WorkloadIdentity:
    """An attributable principal for one agent run / tool call."""

    subject: str                 # e.g. "agent:network-monitor:run-83ac"
    parent: str | None = None    # e.g. "human:secops-operator:priyansh"
    delegation_depth: int = 0

    def __post_init__(self) -> None:
        if not self.subject:
            raise CapabilityError("workload identity requires a subject")
        if self.delegation_depth < 0:
            raise CapabilityError("delegation_depth cannot be negative")


@dataclass(frozen=True)
class CapabilityToken:
    """A scoped, time-boxed, signed authorization for a single action class."""

    subject: str
    capability: str              # "cap:firewall:block-ip"
    resource_constraint: str     # "firewall:edge-a"
    tenant: str
    delegation_depth: int
    issued_at: float
    expires_at: float
    signature: str = ""
    parent: str | None = None

    def _claims(self) -> dict[str, object]:
        """The signed portion — every field except the signature itself."""
        return {
            "subject": self.subject,
            "capability": self.capability,
            "resource_constraint": self.resource_constraint,
            "tenant": self.tenant,
            "delegation_depth": self.delegation_depth,
            "issued_at": round(self.issued_at, 6),
            "expires_at": round(self.expires_at, 6),
            "parent": self.parent,
        }

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def as_dict(self) -> dict[str, object]:
        d = self._claims()
        d["signature"] = self.signature
        return d


def _sign(claims: dict[str, object], key: bytes) -> str:
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass
class CapabilityIssuer:
    """Mints and verifies capability tokens against a protected signing key."""

    key: bytes | str | None = None
    _key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._key = _load_key(self.key)

    def issue(
        self,
        subject: str,
        capability: str,
        resource_constraint: str,
        tenant: str,
        ttl_seconds: float,
        *,
        delegation_depth: int = 0,
        parent: str | None = None,
        now: float | None = None,
    ) -> CapabilityToken:
        if ttl_seconds <= 0:
            raise CapabilityError("ttl_seconds must be positive")
        if delegation_depth > MAX_DELEGATION_DEPTH:
            raise CapabilityError(
                f"delegation_depth {delegation_depth} exceeds max {MAX_DELEGATION_DEPTH}")
        issued = now if now is not None else time.time()
        token = CapabilityToken(
            subject=subject,
            capability=capability,
            resource_constraint=resource_constraint,
            tenant=tenant,
            delegation_depth=delegation_depth,
            issued_at=issued,
            expires_at=issued + ttl_seconds,
            parent=parent,
        )
        signature = _sign(token._claims(), self._key)
        return CapabilityToken(**{**token._claims(), "signature": signature})  # type: ignore[arg-type]

    def delegate(
        self,
        parent_token: CapabilityToken,
        new_subject: str,
        *,
        ttl_seconds: float | None = None,
        now: float | None = None,
    ) -> CapabilityToken:
        """Issue a child capability one level deeper, never wider than the parent.

        The child inherits the parent's capability/resource/tenant scope and
        cannot outlive it; delegation depth strictly increases and is capped.
        """
        self.verify_signature(parent_token)
        now = now if now is not None else time.time()
        if parent_token.is_expired(now):
            raise CapabilityError("cannot delegate an expired capability")
        remaining = parent_token.expires_at - now
        ttl = remaining if ttl_seconds is None else min(ttl_seconds, remaining)
        return self.issue(
            subject=new_subject,
            capability=parent_token.capability,
            resource_constraint=parent_token.resource_constraint,
            tenant=parent_token.tenant,
            ttl_seconds=ttl,
            delegation_depth=parent_token.delegation_depth + 1,
            parent=parent_token.subject,
            now=now,
        )

    def verify_signature(self, token: CapabilityToken) -> None:
        expected = _sign(token._claims(), self._key)
        if not hmac.compare_digest(expected, token.signature):
            raise CapabilityError("capability signature invalid (forged or tampered)")

    def verify(
        self,
        token: CapabilityToken,
        *,
        capability: str,
        resource_constraint: str,
        tenant: str,
        now: float | None = None,
    ) -> None:
        """Fail closed unless the token is authentic, unexpired, and in scope."""
        self.verify_signature(token)
        if token.is_expired(now):
            raise CapabilityError("capability expired")
        if token.capability != capability:
            raise CapabilityError(
                f"capability mismatch: token grants {token.capability!r}, "
                f"action needs {capability!r}")
        if token.resource_constraint != resource_constraint:
            raise CapabilityError(
                f"resource mismatch: token scoped to {token.resource_constraint!r}, "
                f"action targets {resource_constraint!r}")
        if token.tenant != tenant:
            raise CapabilityError(
                f"tenant mismatch: token for {token.tenant!r}, action in {tenant!r}")
        if token.delegation_depth > MAX_DELEGATION_DEPTH:
            raise CapabilityError("delegation depth exceeds maximum")
