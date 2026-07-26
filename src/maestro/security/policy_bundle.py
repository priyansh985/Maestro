"""Signed policy bundles + two-person change control (Governance Plane / L6).

CTRL-L6-03. The rest of the enforcement stack answers *"is this action
authorized under the current policy?"*. This module answers the governance
question one level up: *"who authorized the **policy itself**, and can it be
tampered with?"* — the MAESTRO L6 concern of policy-as-code with change control.

Today the executor's allow-list of intents lives in code (``INTENT_REGISTRY``).
That is fine for integrity of the *binary*, but it means a policy change is an
ordinary code edit: a single actor (or a bug, or a supply-chain tamper) can widen
what the agent may do with no signature and no second pair of eyes. This module
makes the *effective policy* a first-class, tamper-evident artifact:

* A :class:`PolicyBundle` is an immutable, versioned, content-addressed statement
  of the effective allow-list (plus governance metadata / limits). Its ``digest``
  is a sha256 over a canonical encoding, so any change to its content changes its
  identity.
* Activating a bundle requires a **two-person change** (four-eyes / separation of
  duties): the actor who *proposes* a change may not be the one who *approves* it.
  Only once a distinct approver signs off is the bundle HMAC-signed and made
  active — the same signing discipline the capability and ledger layers use.
* The active bundle's signature is re-verified **on every read** (fail-closed): a
  tampered active bundle raises, and the executor treats that as a denial. This is
  what lets the Policy Enforcement Point trust the allow-list it consults at the
  side-effect boundary.
* Every governed change (an activation) is recorded in the tamper-evident audit
  ledger — version, proposer, approvers, digest, provenance — never any secret.

Bootstrap is explicit: :meth:`PolicyRegistry.genesis` establishes v1 as the
deploy-time baseline (single authority — there is no prior policy to approve a
change *against*), and is signed for integrity but is not itself a ledger event.
Every *subsequent* version must go through propose → approve → activate. This
keeps the honest distinction the audit relies on: the baseline ships with the
platform; every *change* to it is two-person-approved and auditable.

Production seam: an external policy store with real signer identities (an OIDC /
KMS-backed key per approver, a code-review/change-ticket gate) rather than a
single shared HMAC key. That changes *where the approver identities and keys come
from*, not the two-person invariant or the fail-closed verification this module
enforces.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .identity import _load_key
from .ledger import Ledger


class PolicyChangeError(Exception):
    """Raised when a bundle is unsigned/tampered, or a change violates the
    two-person rule or the version chain (fail-closed)."""


@dataclass(frozen=True)
class PolicyBundle:
    """An immutable, versioned statement of the policy the executor enforces.

    The enforced clause at the side-effect boundary today is ``allowed_intents``
    (the governed allow-list). ``limits`` carries the rest of the envelope
    (budget/breaker knobs) as signed, auditable metadata so the active policy is
    fully legible in one artifact; those numeric limits are enforced by their own
    controls (CTRL-L3-03 budget, CTRL-L4-04 breaker), not double-claimed here.
    """

    version: int
    allowed_intents: tuple[str, ...]
    limits: tuple[tuple[str, float], ...] = ()
    parent_digest: str | None = None
    created_at: float = 0.0
    provenance: str = ""

    @classmethod
    def create(
        cls,
        *,
        version: int,
        allowed_intents: Iterable[str],
        limits: Mapping[str, float] | None = None,
        parent_digest: str | None = None,
        provenance: str = "",
        created_at: float | None = None,
    ) -> PolicyBundle:
        """Build a bundle, normalizing collections so the ``digest`` is stable
        regardless of input ordering."""
        return cls(
            version=version,
            allowed_intents=tuple(allowed_intents),
            limits=tuple(sorted((limits or {}).items())),
            parent_digest=parent_digest,
            created_at=time.time() if created_at is None else created_at,
            provenance=provenance,
        )

    def canonical(self) -> dict[str, object]:
        """Order-independent view used for the content digest."""
        return {
            "version": self.version,
            "allowed_intents": sorted(self.allowed_intents),
            "limits": sorted((k, v) for k, v in self.limits),
            "parent_digest": self.parent_digest,
            "created_at": round(self.created_at, 6),
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        payload = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def permits(self, intent: str) -> bool:
        """True if the intent is in this bundle's governed allow-list."""
        return intent in self.allowed_intents

    def limit(self, name: str, default: float | None = None) -> float | None:
        for k, v in self.limits:
            if k == name:
                return v
        return default

    def as_dict(self) -> dict[str, object]:
        d = self.canonical()
        d["digest"] = self.digest()
        return d


@dataclass(frozen=True)
class ActivationRecord:
    """A bundle that has cleared the change process and been signed active."""

    bundle: PolicyBundle
    proposer: str
    approvers: tuple[str, ...]
    activated_at: float
    signature: str

    def as_dict(self) -> dict[str, object]:
        return {
            "bundle": self.bundle.as_dict(),
            "proposer": self.proposer,
            "approvers": list(self.approvers),
            "activated_at": round(self.activated_at, 6),
            "signature": self.signature,
        }


@dataclass
class _ChangeRequest:
    bundle: PolicyBundle
    proposer: str
    approvers: list[str] = field(default_factory=list)


class PolicyRegistry:
    """Holds the active signed policy bundle and enforces two-person change.

    * :meth:`genesis` establishes v1 (deploy-time baseline, single authority).
    * :meth:`propose` opens a change request for the next version (its
      ``parent_digest`` must chain to the current active bundle).
    * :meth:`approve` records a *distinct* approver's sign-off; the change
      activates only once ``min_approvals`` approvers — none of them the
      proposer — have signed (separation of duties).
    * :meth:`active` re-verifies the active bundle's HMAC on every call and raises
      if it was tampered, so the executor can treat a bad policy as fail-closed.
    """

    def __init__(
        self,
        *,
        key: bytes | str | None = None,
        ledger: Ledger | None = None,
        min_approvals: int = 1,
        clock: object | None = None,
    ) -> None:
        self._key = _load_key(key)
        self._ledger = ledger
        #: distinct approvers required *in addition to* the proposer.
        self._min_approvals = max(1, min_approvals)
        self._clock = clock if clock is not None else time.time
        self._active: ActivationRecord | None = None
        self._pending: dict[str, _ChangeRequest] = {}
        self._seq = 0

    # -- signing ------------------------------------------------------------- #
    def _activation_payload(
        self, bundle: PolicyBundle, proposer: str,
        approvers: Iterable[str], activated_at: float,
    ) -> bytes:
        return json.dumps(
            {
                "digest": bundle.digest(),
                "version": bundle.version,
                "proposer": proposer,
                "approvers": sorted(approvers),
                "activated_at": round(activated_at, 6),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _sign(
        self, bundle: PolicyBundle, *, proposer: str, approvers: tuple[str, ...],
    ) -> ActivationRecord:
        at = float(self._clock())  # type: ignore[operator]
        sig = hmac.new(
            self._key, self._activation_payload(bundle, proposer, approvers, at),
            hashlib.sha256).hexdigest()
        return ActivationRecord(bundle, proposer, approvers, at, sig)

    def _verify(self, rec: ActivationRecord) -> None:
        expected = hmac.new(
            self._key,
            self._activation_payload(rec.bundle, rec.proposer, rec.approvers, rec.activated_at),
            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, rec.signature):
            raise PolicyChangeError(
                "active policy bundle signature invalid (forged or tampered)")

    # -- lifecycle ----------------------------------------------------------- #
    def genesis(self, bundle: PolicyBundle, *, established_by: str) -> ActivationRecord:
        """Establish the v1 baseline. Single authority (bootstrap) — there is no
        prior policy to approve a change against — signed for integrity."""
        if self._active is not None:
            raise PolicyChangeError("genesis already established")
        if bundle.version != 1:
            raise PolicyChangeError("genesis bundle must be version 1")
        if bundle.parent_digest is not None:
            raise PolicyChangeError("genesis bundle must have no parent")
        rec = self._sign(bundle, proposer=established_by, approvers=())
        self._active = rec
        return rec

    def propose(self, bundle: PolicyBundle, *, proposer: str) -> str:
        """Open a change request for the next policy version. Returns its id."""
        active = self.active()  # fail-closed: no valid baseline → cannot change it
        if bundle.version != active.bundle.version + 1:
            raise PolicyChangeError(
                f"proposed version {bundle.version} must be "
                f"{active.bundle.version + 1} (active + 1)")
        if bundle.parent_digest != active.bundle.digest():
            raise PolicyChangeError(
                "proposed bundle does not chain to the active policy "
                "(parent_digest mismatch)")
        self._seq += 1
        request_id = f"chg-{self._seq:04d}"
        self._pending[request_id] = _ChangeRequest(bundle, proposer)
        return request_id

    def approve(self, request_id: str, *, approver: str) -> ActivationRecord | None:
        """Record a distinct approver's sign-off; activate once quorum is met.

        Returns the new :class:`ActivationRecord` when the change activates, or
        ``None`` while it still needs more approvals. Raises on a two-person-rule
        violation (self-approval, duplicate approval) or a stale change.
        """
        cr = self._pending.get(request_id)
        if cr is None:
            raise PolicyChangeError(f"unknown change request {request_id!r}")
        if approver == cr.proposer:
            raise PolicyChangeError(
                "the proposer may not approve their own change (two-person rule)")
        if approver in cr.approvers:
            raise PolicyChangeError(f"{approver!r} has already approved this change")
        cr.approvers.append(approver)
        if len(cr.approvers) < self._min_approvals:
            return None

        # Re-validate against the *current* active policy at activation time so
        # two concurrent changes cannot both apply against a stale baseline.
        active = self.active()
        if (cr.bundle.version != active.bundle.version + 1
                or cr.bundle.parent_digest != active.bundle.digest()):
            del self._pending[request_id]
            raise PolicyChangeError(
                "stale change: the active policy advanced since this was proposed")

        rec = self._sign(cr.bundle, proposer=cr.proposer, approvers=tuple(cr.approvers))
        self._active = rec
        del self._pending[request_id]
        self._record(rec)
        return rec

    def active(self) -> ActivationRecord:
        """Return the active record, re-verifying its signature (fail-closed)."""
        if self._active is None:
            raise PolicyChangeError("no active policy bundle")
        self._verify(self._active)
        return self._active

    @property
    def pending(self) -> dict[str, tuple[str, tuple[str, ...]]]:
        """Introspection: request_id -> (proposer, approvers-so-far)."""
        return {rid: (cr.proposer, tuple(cr.approvers)) for rid, cr in self._pending.items()}

    # -- audit --------------------------------------------------------------- #
    def _record(self, rec: ActivationRecord) -> None:
        """Append a governed-change event to the tamper-evident ledger.

        Only content-addressed, non-secret governance facts are recorded (digest,
        version, proposer, approvers, provenance) — never a key or raw policy
        secret.
        """
        if self._ledger is None:
            return
        self._ledger.append(
            event_type="policy.bundle.activated",
            actor_identity=rec.proposer,
            decision="activated",
            input_hash=rec.bundle.digest(),
            policy_digest=rec.bundle.digest(),
            detail={
                "version": rec.bundle.version,
                "proposer": rec.proposer,
                "approvers": list(rec.approvers),
                "provenance": rec.bundle.provenance,
                "allowed_intents": list(rec.bundle.allowed_intents),
            },
        )


def genesis_registry(
    allowed_intents: Iterable[str],
    *,
    key: bytes | str,
    ledger: Ledger | None = None,
    limits: Mapping[str, float] | None = None,
    min_approvals: int = 1,
    provenance: str = "genesis: platform-provisioned baseline policy",
    established_by: str = "platform:bootstrap",
) -> PolicyRegistry:
    """Build a :class:`PolicyRegistry` with a v1 genesis bundle admitting exactly
    ``allowed_intents``. Subsequent changes require two-person approval."""
    registry = PolicyRegistry(key=key, ledger=ledger, min_approvals=min_approvals)
    bundle = PolicyBundle.create(
        version=1,
        allowed_intents=allowed_intents,
        limits=limits,
        parent_digest=None,
        provenance=provenance,
    )
    registry.genesis(bundle, established_by=established_by)
    return registry
