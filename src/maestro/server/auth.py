"""Zero-trust authentication + RBAC for the control-plane API (CTRL-L4-03, BP3.1).

The control-plane REST API drives the *real* enforcement stack — submitting an
alert runs the live :class:`~maestro.platform.AgentPlatform`, ``/reset`` clears
the tamper-evident ledger, ``/halt`` trips the kill switch. Leaving that surface
unauthenticated is a confused-deputy waiting to happen: anyone who can reach the
port inherits the operator's authority. This module closes that gap by putting a
**fail-closed** identity + role boundary in front of every control-plane route.

Design, consistent with the rest of the repository (offline, stdlib-only,
deterministic):

* A bearer token is a compact ``<payload>.<sig>`` string: base64url(JSON claims)
  signed with HMAC-SHA256 over a protected key (the same ``MAESTRO_SIGNING_KEY``
  the capability layer uses). No third-party JWT dependency; verification is
  ``hmac.compare_digest`` so it is tamper- and forgery-resistant.
* Every principal carries a ``tenant`` and a ``role``. Roles are totally ordered
  (``viewer < operator < admin``); a route declares the *minimum* role it needs.
* Authentication and authorization **fail closed**: a missing, malformed,
  expired, revoked, or under-privileged token is denied (401/403), never
  defaulted to a permissive identity.

The same boundary guards the whole ``/api`` surface — both the control-plane
routes and the model-testing/connectors routes — and a deterministic
:class:`RateLimiter` bounds inbound requests per principal (fail-closed 429).

Production seams (documented, not built here): OIDC / SSO login and CLI device
flow instead of statically issued tokens, an external RBAC/ABAC policy store, and
a shared (Redis) rate-limit store so the limit holds across replicas. Those
change *where the principal comes from* and *where the counter lives*, not the
boundary this module enforces.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from enum import IntEnum

from fastapi import Header, HTTPException

SIGNING_KEY_ENV = "MAESTRO_SIGNING_KEY"
#: The tenant the process-scoped control plane serves (single-tenant today; a
#: multi-tenant plane is a later BP3 increment). A principal for another tenant
#: is denied cross-tenant.
DEFAULT_CONTROL_PLANE_TENANT = "default"


class AuthError(Exception):
    """Raised when a token is missing, malformed, expired, revoked, or forged."""


class Role(IntEnum):
    """Totally ordered RBAC roles; a route requires a *minimum* role."""

    VIEWER = 1     # read the truth audit, ledger, metrics, state
    OPERATOR = 2   # run alerts, perimeter/critique, kill switch
    ADMIN = 3      # destructive: reset (clears the ledger), provisioning

    @classmethod
    def parse(cls, name: str) -> Role:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise AuthError(f"unknown role {name!r}") from exc


@dataclass(frozen=True)
class Principal:
    """An authenticated caller of the control plane."""

    subject: str          # "svc:soc-console" | "user:priyansh"
    tenant: str
    role: Role
    kind: str = "service_account"   # "service_account" | "user"
    jti: str = ""                   # token id, for revocation

    def as_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "tenant": self.tenant,
            "role": self.role.name.lower(),
            "kind": self.kind,
            "jti": self.jti,
        }

    @staticmethod
    def anonymous(tenant: str = DEFAULT_CONTROL_PLANE_TENANT) -> Principal:
        """The synthetic principal used only when enforcement is disabled
        (``mitigation.zero_trust_api=false`` — the paper's unauthenticated
        baseline). It is deliberately full-privilege so turning enforcement off
        restores the legacy behavior exactly, and is never minted from a token."""
        return Principal("anonymous", tenant, Role.ADMIN, kind="anonymous")


def _load_key(key: bytes | str | None) -> bytes:
    if key is None:
        key = os.environ.get(SIGNING_KEY_ENV, "")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise AuthError(f"no signing key: pass key=... or set {SIGNING_KEY_ENV}")
    return key


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class AuthService:
    """Issues and verifies control-plane bearer tokens against a protected key."""

    key: bytes | str | None = None

    def __post_init__(self) -> None:
        self._key = _load_key(self.key)
        self._revoked: set[str] = set()

    def issue(
        self,
        subject: str,
        *,
        tenant: str = DEFAULT_CONTROL_PLANE_TENANT,
        role: Role = Role.OPERATOR,
        kind: str = "service_account",
        ttl_seconds: float = 3600.0,
        jti: str | None = None,
        now: float | None = None,
    ) -> str:
        """Mint a signed bearer token. In production the subject/role would come
        from an OIDC identity; here they are stated explicitly and signed."""
        if ttl_seconds <= 0:
            raise AuthError("ttl_seconds must be positive")
        issued = now if now is not None else time.time()
        token_id = jti if jti is not None else os.urandom(8).hex()
        claims = {
            "sub": subject,
            "tenant": tenant,
            "role": role.name,
            "kind": kind,
            "jti": token_id,
            "iat": round(issued, 6),
            "exp": round(issued + ttl_seconds, 6),
        }
        payload = _b64u_encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        sig = hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def authenticate(self, token: str, *, now: float | None = None) -> Principal:
        """Return the token's :class:`Principal`, or raise :class:`AuthError`.

        Fails closed on every failure mode: malformed structure, bad signature,
        expiry, revocation, or unparseable claims.
        """
        if not token or token.count(".") != 1:
            raise AuthError("malformed token")
        payload, sig = token.split(".", 1)
        expected = hmac.new(
            self._key, payload.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise AuthError("signature invalid (forged or tampered)")
        try:
            claims = json.loads(_b64u_decode(payload))
        except (ValueError, json.JSONDecodeError) as exc:
            raise AuthError("unparseable claims") from exc
        exp = float(claims.get("exp", 0.0))
        if (now if now is not None else time.time()) >= exp:
            raise AuthError("token expired")
        jti = str(claims.get("jti", ""))
        if jti in self._revoked:
            raise AuthError("token revoked")
        return Principal(
            subject=str(claims["sub"]),
            tenant=str(claims["tenant"]),
            role=Role.parse(str(claims["role"])),
            kind=str(claims.get("kind", "service_account")),
            jti=jti,
        )

    def revoke(self, jti: str) -> None:
        """Add a token id to the revocation set (fail-closed thereafter)."""
        self._revoked.add(jti)


# --------------------------------------------------------------------------- #
# Per-principal rate limiting (front-door abuse / DoS control).
# --------------------------------------------------------------------------- #
@dataclass
class RateLimiter:
    """A deterministic token-bucket rate limiter keyed per principal.

    One bucket per key (``tenant:subject``): each request consumes a token,
    tokens refill continuously at ``refill_per_sec`` up to ``capacity`` (the
    burst). ``allow`` is a pure function of the bucket state and the supplied
    ``now``, so it is testable without wall-clock flakiness. ``capacity <= 0``
    disables limiting (every call allowed).

    This is distinct from CTRL-L3-03 (the agent *autonomy budget*, which bounds
    tool calls on the live loop): this bounds inbound API requests at the front
    door (TB0), so a single credential cannot exhaust the control plane. In
    production this would move to a shared store (Redis) so the limit holds
    across replicas; here it is in-process and deterministic.
    """

    capacity: float
    refill_per_sec: float

    def __post_init__(self) -> None:
        # key -> (tokens_remaining, last_seen_ts)
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, now: float) -> bool:
        """Consume one token for ``key`` at time ``now``; return False if empty."""
        if self.capacity <= 0:
            return True
        tokens, last = self._buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + max(0.0, now - last) * self.refill_per_sec)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True

    @classmethod
    def per_minute(cls, per_min: float) -> RateLimiter | None:
        """Build a limiter allowing ``per_min`` requests/min (burst == per_min).

        Returns ``None`` when ``per_min <= 0`` so the caller can treat "no limit
        configured" and "limiter object" uniformly.
        """
        if per_min <= 0:
            return None
        return cls(capacity=float(per_min), refill_per_sec=per_min / 60.0)


# --------------------------------------------------------------------------- #
# Process-scoped auth state + FastAPI dependencies.
# --------------------------------------------------------------------------- #
@dataclass
class _AuthState:
    enforce: bool = True
    service: AuthService | None = None
    control_plane_tenant: str = DEFAULT_CONTROL_PLANE_TENANT
    rate_limiter: RateLimiter | None = None

    def resolve_service(self) -> AuthService:
        if self.service is None:
            # Lazily build from the environment key so a running server needs no
            # extra wiring; tests inject a fixed-key service via configure_auth.
            self.service = AuthService()
        return self.service


_STATE = _AuthState()


def configure_auth(
    *,
    enforce: bool = True,
    service: AuthService | None = None,
    control_plane_tenant: str = DEFAULT_CONTROL_PLANE_TENANT,
    rate_limiter: RateLimiter | None = None,
) -> None:
    """Configure the process-wide auth boundary (called by ``create_app``/tests)."""
    _STATE.enforce = enforce
    _STATE.service = service
    _STATE.control_plane_tenant = control_plane_tenant
    _STATE.rate_limiter = rate_limiter


def _authenticate_header(authorization: str | None) -> Principal:
    if not _STATE.enforce:
        return Principal.anonymous(_STATE.control_plane_tenant)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):].strip()
    try:
        return _STATE.resolve_service().authenticate(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def require_role(minimum: Role):
    """FastAPI dependency: authenticate and enforce the minimum role, returning
    the :class:`Principal`. Fails closed (401/403).

    Tenant confinement is NOT a check here — it is structural. The control plane
    routes each principal to its own per-tenant ``AgentPlatform``/``Ledger``
    instance (``control_api.py:_TenantPlanes``, CTRL-L4-08), so a principal for
    tenant A physically cannot reach tenant B's data: there is no shared object
    to leak through and no per-call-site scope argument to forget. The
    ``principal.tenant`` claim selects the partition; it is authenticated (signed
    into the token) so it cannot be spoofed.
    """

    def dependency(authorization: str | None = Header(default=None)) -> Principal:
        principal = _authenticate_header(authorization)
        if principal.role < minimum:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"role {principal.role.name.lower()} is below required "
                    f"{minimum.name.lower()}"
                ),
            )
        return principal

    return dependency


def enforce_rate_limit(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: bound inbound requests per principal (fail-closed 429).

    Runs after authentication on the ``/api`` routers. It is a no-op when
    enforcement is off (the paper's open baseline) or no limiter is configured;
    otherwise it keys the bucket by the authenticated ``tenant:subject`` so one
    credential's burst cannot starve another principal or the plane itself.
    """
    limiter = _STATE.rate_limiter
    if not _STATE.enforce or limiter is None:
        return
    principal = _authenticate_header(authorization)
    key = f"{principal.tenant}:{principal.subject}"
    if not limiter.allow(key, time.time()):
        raise HTTPException(
            status_code=429,
            detail=f"rate limit exceeded for principal {principal.subject!r}",
        )


#: Convenience dependencies for the three privilege tiers.
require_viewer = require_role(Role.VIEWER)
require_operator = require_role(Role.OPERATOR)
require_admin = require_role(Role.ADMIN)
